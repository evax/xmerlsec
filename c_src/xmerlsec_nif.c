/*

Copyright (C) 2013 Evax Software <contact@evax.fr>

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.

*/
#include <erl_nif.h>
#include <string.h>
#include <libxml/tree.h>
#include <libxml/xmlmemory.h>
#include <libxml/parser.h>
#include <libxslt/xslt.h>
#include <libxslt/security.h>
#include <xmlsec/xmlsec.h>
#include <xmlsec/xmltree.h>
#include <xmlsec/xmldsig.h>
#include <xmlsec/templates.h>
#include <xmlsec/crypto.h>

static ErlNifResourceType* xmerlsec_nif_resource_keysmngr;

typedef struct xmerlsec_keysmngr {
    xmlSecKeysMngrPtr mngr;
} xmerlsec_keysmngr_t;

#define ERROR_TUPLE(env, x) \
    enif_make_tuple2(env, enif_make_atom(env, "error"), enif_make_atom(env, x))

#define OK_TUPLE(env, x) \
    enif_make_tuple2(env, enif_make_atom(env, "ok"), x)

static ERL_NIF_TERM keysmngr_create(ErlNifEnv *env, int argc,
                                    const ERL_NIF_TERM argv[])
{
    xmerlsec_keysmngr_t* mngr = enif_alloc_resource(
            xmerlsec_nif_resource_keysmngr,
            sizeof(xmerlsec_keysmngr_t));
    mngr->mngr = xmlSecKeysMngrCreate();
    if (mngr->mngr == NULL) {
        enif_release_resource(mngr);
        return ERROR_TUPLE(env, "keysmngr_create");
    }
    if (xmlSecCryptoAppDefaultKeysMngrInit(mngr->mngr) < 0) {
        xmlSecKeysMngrDestroy(mngr->mngr);
        enif_release_resource(mngr);
        return ERROR_TUPLE(env, "keysmngr_init");
    }
    return OK_TUPLE(env, enif_make_resource(env, mngr));
}

static ERL_NIF_TERM keysmngr_destroy(ErlNifEnv *env, int argc,
                                     const ERL_NIF_TERM argv[])
{
    xmerlsec_keysmngr_t* mngr;
    if (!enif_get_resource(env, argv[0], xmerlsec_nif_resource_keysmngr,
                           (void **)&mngr)) {
        return enif_make_badarg(env);
    }
    xmlSecKeysMngrDestroy(mngr->mngr);
    enif_release_resource(mngr);
    return enif_make_atom(env, "ok");
}

static ERL_NIF_TERM keysmngr_add_key_and_cert(ErlNifEnv *env, int argc,
                                     const ERL_NIF_TERM argv[])
{
    xmerlsec_keysmngr_t* mngr;
    if (!enif_get_resource(env, argv[0], xmerlsec_nif_resource_keysmngr,
                           (void **)&mngr)) {
        return enif_make_badarg(env);
    }
    ErlNifBinary keyFile;
    if (!enif_inspect_binary(env, argv[1], &keyFile)) {
        return enif_make_badarg(env);
    }
    ErlNifBinary certFile;
    if (!enif_inspect_binary(env, argv[2], &certFile)) {
        return enif_make_badarg(env);
    }
    xmlSecKeyPtr key;
    key = xmlSecCryptoAppKeyLoad((const char*)keyFile.data,
                                 xmlSecKeyDataFormatPem,
                                 NULL, NULL, NULL);
    if (key == NULL) {
        return ERROR_TUPLE(env, "key_load");
    }
    if (xmlSecKeySetName(key, BAD_CAST keyFile.data) < 0) {
        xmlSecKeyDestroy(key);
        return ERROR_TUPLE(env, "key_setname");
    }
    if (xmlSecCryptoAppKeyCertLoad(key, (const char*)certFile.data,
                                   xmlSecKeyDataFormatPem) < 0) {
        xmlSecKeyDestroy(key);
        return ERROR_TUPLE(env, "key_register_cert");
    }
    if (xmlSecCryptoAppDefaultKeysMngrAdoptKey(mngr->mngr, key) < 0) {
        xmlSecKeyDestroy(key);
        return ERROR_TUPLE(env, "key_adopt");
    }
    return enif_make_atom(env, "ok");
}

static ERL_NIF_TERM keysmngr_add_cert(ErlNifEnv *env, int argc,
                                      const ERL_NIF_TERM argv[])
{
    xmerlsec_keysmngr_t* mngr;
    if (!enif_get_resource(env, argv[0], xmerlsec_nif_resource_keysmngr,
                           (void **)&mngr)) {
        return enif_make_badarg(env);
    }
    ErlNifBinary certFile;
    if (!enif_inspect_binary(env, argv[1], &certFile)) {
        return enif_make_badarg(env);
    }
    if (xmlSecCryptoAppKeysMngrCertLoad(mngr->mngr, (const char*)certFile.data,
                                        xmlSecKeyDataFormatPem,
                                        xmlSecKeyDataTypeTrusted) < 0) {
        return ERROR_TUPLE(env, "cert_load");
    }
    return enif_make_atom(env, "ok");
}

static ERL_NIF_TERM sign(ErlNifEnv *env, int argc,
                         const ERL_NIF_TERM argv[])
{
    ErlNifBinary xmlSrc;
    if (!enif_inspect_binary(env, argv[0], &xmlSrc)) {
        return enif_make_badarg(env);
    }
    ErlNifBinary element;
    if (!enif_inspect_binary(env, argv[1], &element)) {
        return enif_make_badarg(env);
    }
    ErlNifBinary elemNS;
    if (!enif_inspect_binary(env, argv[2], &elemNS)) {
        return enif_make_badarg(env);
    }
    xmerlsec_keysmngr_t* mngr;
    if (!enif_get_resource(env, argv[3], xmerlsec_nif_resource_keysmngr,
                           (void **)&mngr)) {
        return enif_make_badarg(env);
    }
    xmlDocPtr doc = NULL;
    xmlNodePtr signNode = NULL;
    xmlNodePtr refNode = NULL;
    xmlNodePtr keyInfoNode = NULL;
    xmlSecDSigCtxPtr dsigCtx = NULL;

    doc = xmlParseMemory((const char*)xmlSrc.data, xmlSrc.size);
    if ((doc == NULL) || (xmlDocGetRootElement(doc) == NULL)) {
        return ERROR_TUPLE(env, "parse_data");
    }
    xmlNodePtr assertionNode =
        xmlSecFindNode(xmlDocGetRootElement(doc),
                       BAD_CAST element.data,
                       BAD_CAST elemNS.data);
    xmlAttrPtr attr = xmlHasProp(assertionNode, BAD_CAST "ID");
    xmlChar* id = xmlGetProp(assertionNode, BAD_CAST "ID");
    xmlAddID(NULL, doc, id, attr);
    xmlChar* uri = xmlStrncatNew(BAD_CAST "#", id, -1);
    xmlFree(id);

    signNode = xmlSecTmplSignatureCreateNsPref(
                        doc, xmlSecTransformExclC14NId,
                        xmlSecTransformRsaSha1Id, NULL,
                        BAD_CAST "dsig");
    if (signNode == NULL) {
        xmlFreeDoc(doc);
        return ERROR_TUPLE(env, "signature_creation");
    }

    xmlAddChild(assertionNode, signNode);

    refNode = xmlSecTmplSignatureAddReference(
                        signNode, xmlSecTransformSha1Id,
                        NULL, uri, NULL);
    xmlFree(uri);
    if (refNode == NULL) {
        xmlFreeDoc(doc);
        return ERROR_TUPLE(env, "add_reference");
    }
    if (xmlSecTmplReferenceAddTransform(refNode,
                                        xmlSecTransformEnvelopedId) == NULL) {
        xmlFreeDoc(doc);
        return ERROR_TUPLE(env, "envelope_transform");
    }
    if (xmlSecTmplReferenceAddTransform(refNode,
                                        xmlSecTransformExclC14NId) == NULL) {
        xmlFreeDoc(doc);
        return ERROR_TUPLE(env, "c14n_transform");
    }
    keyInfoNode = xmlSecTmplSignatureEnsureKeyInfo(signNode, NULL);
    if (keyInfoNode == NULL) {
        xmlFreeDoc(doc);
        return ERROR_TUPLE(env, "ensure_key_info");
    }
    if (xmlSecTmplKeyInfoAddX509Data(keyInfoNode) == NULL) {
        xmlFreeDoc(doc);
        return ERROR_TUPLE(env, "add_x509_data");
    }
    dsigCtx = xmlSecDSigCtxCreate(mngr->mngr);
    if (dsigCtx == NULL) {
        xmlFreeDoc(doc);
        return ERROR_TUPLE(env, "sig_ctx_create");
    }
    if (xmlSecDSigCtxSign(dsigCtx, signNode) < 0) {
        xmlSecDSigCtxDestroy(dsigCtx);
        xmlFreeDoc(doc);
        return ERROR_TUPLE(env, "ctx_sign");
    }
    xmlChar* outDoc;
    int outDocSize;
    xmlDocDumpMemory(doc, &outDoc, &outDocSize);
    xmlSecDSigCtxDestroy(dsigCtx);
    xmlFreeDoc(doc);
    ErlNifBinary docBin;
    if (!enif_alloc_binary(outDocSize, &docBin)) {
        xmlFree(outDoc);
        return ERROR_TUPLE(env, "out_of_memory");
    }
    memcpy(docBin.data, outDoc, outDocSize);
    xmlFree(outDoc);
    return OK_TUPLE(env, enif_make_binary(env, &docBin));
}

static ERL_NIF_TERM verify(ErlNifEnv *env, int argc,
                           const ERL_NIF_TERM argv[])
{
    ErlNifBinary xmlSrc;
    if (!enif_inspect_binary(env, argv[0], &xmlSrc)) {
        return enif_make_badarg(env);
    }
    ErlNifBinary element;
    if (!enif_inspect_binary(env, argv[1], &element)) {
        return enif_make_badarg(env);
    }
    ErlNifBinary elemNS;
    if (!enif_inspect_binary(env, argv[2], &elemNS)) {
        return enif_make_badarg(env);
    }
    xmerlsec_keysmngr_t* mngr;
    if (!enif_get_resource(env, argv[3], xmerlsec_nif_resource_keysmngr,
                           (void **)&mngr)) {
        return enif_make_badarg(env);
    }
    xmlDocPtr doc = NULL;
    xmlNodePtr node = NULL;
    xmlSecDSigCtxPtr dsigCtx = NULL;
    doc = xmlParseMemory((const char*)xmlSrc.data, xmlSrc.size);
    if ((doc == NULL) || (xmlDocGetRootElement(doc) == NULL)) {
        return ERROR_TUPLE(env, "parse_data");
    }
    xmlNodePtr assertionNode =
        xmlSecFindNode(xmlDocGetRootElement(doc),
                       BAD_CAST element.data,
                       BAD_CAST elemNS.data);
    xmlAttrPtr attr = xmlHasProp(assertionNode, BAD_CAST "ID");
    xmlChar* id = xmlGetProp(assertionNode, BAD_CAST "ID");
    xmlAddID(NULL, doc, id, attr);
    xmlFree(id);
    node = xmlSecFindNode(xmlDocGetRootElement(doc),
                          xmlSecNodeSignature, xmlSecDSigNs);
    if (node == NULL) {
        xmlFreeDoc(doc);
        return ERROR_TUPLE(env, "find_root");
    }
    dsigCtx = xmlSecDSigCtxCreate(mngr->mngr);
    if (dsigCtx == NULL) {
        xmlFreeDoc(doc);
        return ERROR_TUPLE(env, "sig_ctx_create");
    }
    if(xmlSecDSigCtxVerify(dsigCtx, node) < 0) {
        xmlFreeDoc(doc);
        return ERROR_TUPLE(env, "sig_verify");
    }
    ERL_NIF_TERM out = enif_make_atom(env,
                            (dsigCtx->status == xmlSecDSigStatusSucceeded) ?
                                "true" : "false");
    xmlSecDSigCtxDestroy(dsigCtx);
    xmlFreeDoc(doc);
    return OK_TUPLE(env, out);
}

static int load(ErlNifEnv *env, void **priv, ERL_NIF_TERM info)
{
    xmerlsec_nif_resource_keysmngr = enif_open_resource_type(
                        env, "xmerlsec_nif",
                        "xmerlsec_nif_resource_keysmngr",
                        NULL,
                        ERL_NIF_RT_CREATE | ERL_NIF_RT_TAKEOVER,
                        0);
    xsltSecurityPrefsPtr xsltSecPrefs = NULL;
    xmlInitParser();
    LIBXML_TEST_VERSION
    xmlLoadExtDtdDefaultValue = XML_DETECT_IDS | XML_COMPLETE_ATTRS;
    xmlSubstituteEntitiesDefault(1);
    xmlIndentTreeOutput = 1;
    xsltSecPrefs = xsltNewSecurityPrefs();
    *priv = (void*)xsltSecPrefs;
    xsltSetSecurityPrefs(xsltSecPrefs, XSLT_SECPREF_READ_FILE,
                         xsltSecurityForbid);
    xsltSetSecurityPrefs(xsltSecPrefs, XSLT_SECPREF_WRITE_FILE,
                         xsltSecurityForbid);
    xsltSetSecurityPrefs(xsltSecPrefs, XSLT_SECPREF_CREATE_DIRECTORY,
                         xsltSecurityForbid);
    xsltSetSecurityPrefs(xsltSecPrefs, XSLT_SECPREF_READ_NETWORK,
                         xsltSecurityForbid);
    xsltSetSecurityPrefs(xsltSecPrefs, XSLT_SECPREF_WRITE_NETWORK,
                         xsltSecurityForbid);
    if (xmlSecInit() < 0) {
        return -1;
    }
    if (xmlSecCheckVersion() != 1) {
        return -1;
    }
    if (xmlSecCryptoAppInit(NULL) < 0) {
        return -1;
    }
    if (xmlSecCryptoInit() < 0) {
        return -1;
    }
    return 0;
}

static int reload(ErlNifEnv *env, void **priv, ERL_NIF_TERM info)
{
    return 0;
}

static int upgrade(ErlNifEnv *env, void **priv,
                   void **old_priv, ERL_NIF_TERM info)
{
    *priv = *old_priv;
    return 0;
}

static void unload(ErlNifEnv *env, void *priv)
{
    xmlSecCryptoShutdown();
    xmlSecCryptoAppShutdown();
    xmlSecShutdown();
    xsltFreeSecurityPrefs((xsltSecurityPrefsPtr)priv);
    xsltCleanupGlobals();
    xmlCleanupParser();
}

static ErlNifFunc funcs[] =
    {
        {"keysmngr_create", 0, keysmngr_create},
        {"keysmngr_destroy", 1, keysmngr_destroy},
        {"keysmngr_add_key_and_cert", 3, keysmngr_add_key_and_cert},
        {"keysmngr_add_cert", 2, keysmngr_add_cert},
        {"sign", 4, sign},
        {"verify", 4, verify}
    };

ERL_NIF_INIT(xmerlsec_nif, funcs, &load, &reload, &upgrade, &unload);

