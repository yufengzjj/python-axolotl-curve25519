/* tell python that PyArg_ParseTuple(t#) means Py_ssize_t, not int */
#define PY_SSIZE_T_CLEAN
#include <Python.h>
#if (PY_VERSION_HEX < 0x02050000)
typedef int Py_ssize_t;
#endif

/* This is required for compatibility with Python 2. */
#if PY_MAJOR_VERSION >= 3
#include <bytesobject.h>
#define y "y"
#else
#define PyBytes_FromStringAndSize PyString_FromStringAndSize
#define y "t"
#endif

int curve25519_sign(unsigned char *signature_out,
                    const unsigned char *curve25519_privkey,
                    const unsigned char *msg, const unsigned long msg_len,
                    const unsigned char *random);

int curve25519_verify(const unsigned char *signature,
                      const unsigned char *curve25519_pubkey,
                      const unsigned char *msg, const unsigned long msg_len);

int curve25519_donna(char *mypublic,
                     const char *secret, const char *basepoint);
unsigned char L[] = {0xED, 0xD3, 0xF5, 0x5C, 0x1A, 0x63, 0x12, 0x58, 0xD6, 0x9C,
                     0xF7, 0xA2, 0xDE, 0xF9, 0xDE, 0x14, 0x00, 0x00, 0x00, 0x00,
                     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                     0x00, 0x10};
int sc_is_canonical(const unsigned char *k, int len)
{
    if (len != 32)
        return 0;
    int v2 = 0;
    int v3 = 1;
    for (int i = 31LL; i != -1; --i)
    {
        int v5 = k[i];
        int v6 = L[i];
        v2 = v3 & ((v5 - v6) >> 8) | (unsigned char)v2;
        v3 &= ((v6 ^ v5) - 1) >> 8;
    }
    return (unsigned char)v2 != 0;
}

int libsodium_is_zero(const unsigned char *k, int len)
{
    char v2;
    unsigned char i;

    for (i = 0; len; --len)
    {
        v2 = *k++;
        i |= v2;
    }
    return (((unsigned int)i - 1) >> 8) & 1;
}


static PyObject *
calculateSignature(PyObject *self, PyObject *args)
{
    const char *random;
    const char *privatekey;
    const char *message;
    char signature[64];
    Py_ssize_t randomlen, privatekeylen, messagelen;

    if (!PyArg_ParseTuple(args, y"#"y"#"y"#:calculateSignature",
                          &random, &randomlen, &privatekey, &privatekeylen, &message, &messagelen))
        return NULL;
    if (privatekeylen != 32)
    {
        PyErr_SetString(PyExc_ValueError, "private key must be 32-byte string");
        return NULL;
    }
    if (randomlen != 64)
    {
        PyErr_SetString(PyExc_ValueError, "random must be 64-byte string");
        return NULL;
    }

    curve25519_sign((unsigned char *)signature, (unsigned char *)privatekey,
                    (unsigned char *)message, messagelen, (unsigned char *)random);

    return PyBytes_FromStringAndSize((char *)signature, 64);
}

static PyObject *
verifySignature(PyObject *self, PyObject *args)
{
    const char *publickey;
    const char *message;
    const char *signature;

    Py_ssize_t publickeylen, messagelen, signaturelen;

    if (!PyArg_ParseTuple(args, y"#"y"#"y"#:verifySignature",
                          &publickey, &publickeylen, &message, &messagelen, &signature, &signaturelen))
        return NULL;

    if (publickeylen != 32)
    {
        PyErr_SetString(PyExc_ValueError, "publickey must be 32-byte string");
        return NULL;
    }
    if (signaturelen != 64)
    {
        PyErr_SetString(PyExc_ValueError, "signature must be 64-byte string");
        return NULL;
    }

    int result = curve25519_verify((unsigned char *)signature, (unsigned char *)publickey,
                                   (unsigned char *)message, messagelen);

    return Py_BuildValue("i", result);
}

static PyObject *
generatePrivateKey(PyObject *self, PyObject *args)
{
    char *random;
    Py_ssize_t randomlen;

    if (!PyArg_ParseTuple(args, y "#:generatePrivateKey", &random, &randomlen))
    {
        return NULL;
    }

    if (randomlen != 32)
    {
        PyErr_SetString(PyExc_ValueError, "random must be 32-byte string");
        return NULL;
    }
    random[0] &= 248;
    random[31] &= 127;
    random[31] |= 64;

    return PyBytes_FromStringAndSize((char *)random, 32);
}

static PyObject *
generatePublicKey(PyObject *self, PyObject *args)
{
    const char *private;
    char mypublic[32];
    char basepoint[32] = {9};
    Py_ssize_t privatelen;
    if (!PyArg_ParseTuple(args, y"#:generatePublicKey", &private, &privatelen))
        return NULL;
    if (privatelen != 32)
    {
        PyErr_SetString(PyExc_ValueError, "input must be 32-byte string");
        return NULL;
    }
    curve25519_donna(mypublic, private, basepoint);
    return PyBytes_FromStringAndSize((char *)mypublic, 32);
}

static PyObject *
calculateAgreement(PyObject *self, PyObject *args)
{
    const char *myprivate, *theirpublic;
    char shared_key[32];
    Py_ssize_t myprivatelen, theirpubliclen;
    if (!PyArg_ParseTuple(args, y"#"y"#:calculateAgreement",
                          &myprivate, &myprivatelen, &theirpublic, &theirpubliclen))
        return NULL;
    if (myprivatelen != 32)
    {
        PyErr_SetString(PyExc_ValueError, "input must be 32-byte string");
        return NULL;
    }
    if (theirpubliclen != 32)
    {
        PyErr_SetString(PyExc_ValueError, "input must be 32-byte string");
        return NULL;
    }
    curve25519_donna(shared_key, myprivate, theirpublic);
    return PyBytes_FromStringAndSize((char *)shared_key, 32);
}

#include "ge.h"

static PyObject *
acs_generate_native_blind(PyObject *self, PyObject *args)
{
    const unsigned char *h, *k;
    unsigned char key[32];

    Py_ssize_t h_len, k_len;
    if (!PyArg_ParseTuple(args, y"#"y"#:acs_generate_native_blind",
                          &h, &h_len, &k, &k_len))
        return NULL;
    if (h_len != 32 || k_len != 32)
    {
        PyErr_SetString(PyExc_ValueError, "input must be 32-byte string");
        return NULL;
    }
    unsigned char k_buf[32];
    memcpy(k_buf, k, k_len);
    k_buf[0] &= 0xF8u;
    k_buf[31] = k_buf[31] & 0x3F | 0x40;
    ge_p3 p_k;
    ge_scalarmult_base(&p_k, k_buf);
    ge_p3 p_h;
    hash_to_point(&p_h, h, h_len);
    ge_p3 r;
    ge_p3_add(&r, &p_k, &p_h);
    ge_p3_tobytes(key, &r);
    return PyBytes_FromStringAndSize((char *)key, 32);
}

static PyObject *
acs_generate_native_unblind(PyObject *self, PyObject *args)
{
    const unsigned char *acs_public_key, *k, *signed_credential;
    unsigned char key[32];

    Py_ssize_t acs_public_key_len, k_len, signed_credential_len;
    if (!PyArg_ParseTuple(args, y"#"y"#"y"#:acs_generate_native_unblind",
                          &acs_public_key, &acs_public_key_len,&k, &k_len, &signed_credential, &signed_credential_len))
        return NULL;
    if (acs_public_key_len != 32 || k_len != 32||signed_credential_len!=32)
    {
        PyErr_SetString(PyExc_ValueError, "input must be 32-byte string");
        return NULL;
    }
    unsigned char k_buf[32];
    memcpy(k_buf, k, k_len);
    k_buf[0] &= 0xF8u;
    k_buf[31] = k_buf[31] & 0x3F | 0x40;
    ge_p3 pk_p,sc_p,sc_r,p,kpk_r;
    ge_frombytes_negate_vartime(&sc_p,signed_credential);
    ge_neg(&sc_r,&sc_p);
    ge_frombytes_negate_vartime(&pk_p,acs_public_key);
    ge_scalarmult(&kpk_r,k_buf,&pk_p);
    ge_p3 r;
    ge_p3_add(&r, &sc_r, &kpk_r);
    ge_p3_tobytes(key, &r);
    return PyBytes_FromStringAndSize((char *)key, 32);
}

static PyObject *
acs_verify_if_valid(PyObject *self, PyObject *args)
{
    const unsigned char *k;
    Py_ssize_t k_len;
    if (!PyArg_ParseTuple(args, y"#:acs_verify_if_valid", &k, &k_len))
        return NULL;
    if (k_len != 32)
    {
        PyErr_SetString(PyExc_ValueError, "input must be 32-byte string");
        return Py_False;
    }
    return PyBool_FromLong(sc_is_canonical(k, k_len) && !libsodium_is_zero(k, k_len));
}

static PyMethodDef curve25519_functions[] = {
        {"calculateSignature", calculateSignature, METH_VARARGS, "random+privatekey+message->signature"},
        {"verifySignature", verifySignature, METH_VARARGS, "publickey+message+signature->valid"},
        {"generatePrivateKey", generatePrivateKey, METH_VARARGS, "data->private"},
        {"generatePublicKey", generatePublicKey, METH_VARARGS, "private->public"},
        {"calculateAgreement", calculateAgreement, METH_VARARGS, "private+public->shared"},
        {"acs_generate_native_blind", acs_generate_native_blind, METH_VARARGS, "h+k->key"},
        {"acs_generate_native_unblind", acs_generate_native_unblind, METH_VARARGS, "acs_public_key+k+signed_credential->key"},
        {"acs_verify_if_valid", acs_verify_if_valid, METH_VARARGS, "k->bool"},
        {NULL, NULL, 0, NULL},
};

#if PY_MAJOR_VERSION >= 3
static struct PyModuleDef
    curve25519_module = {
        PyModuleDef_HEAD_INIT,
        "axolotl_curve25519",
        NULL,
        NULL,
        curve25519_functions,
};

PyObject *
PyInit_axolotl_curve25519(void)
{
    return PyModule_Create(&curve25519_module);
}
#else

PyMODINIT_FUNC
initaxolotl_curve25519(void)
{
    (void)Py_InitModule("axolotl_curve25519", curve25519_functions);
}

#endif
