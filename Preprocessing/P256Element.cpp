/*
 * P256Element.cpp
 *
 */

#include "P256Element.h"

#include "Math/gfp.hpp"


EC_GROUP* P256Element::curve;

void P256Element::init()
{
    curve = EC_GROUP_new_by_curve_name(NID_secp256k1);
    assert(curve != 0);
    auto modulus = EC_GROUP_get0_order(curve);
    auto mod = BN_bn2dec(modulus);
    Scalar::init_field(mod, false);
    free(mod);
}

void P256Element::finish()
{
    EC_GROUP_free(curve);
}

P256Element::P256Element()
{
    point = EC_POINT_new(curve);
    assert(point != 0);
    assert(EC_POINT_set_to_infinity(curve, point) != 0);
}

P256Element::P256Element(const Scalar& other) :
        P256Element()
{
    BIGNUM* exp = BN_new();
    BN_dec2bn(&exp, bigint(other).get_str().c_str());
    assert(EC_POINT_mul(curve, point, exp, 0, 0, 0) != 0);
    BN_free(exp);
}

P256Element::P256Element(word other) :
        P256Element()
{
    BIGNUM* exp = BN_new();
    BN_dec2bn(&exp, to_string(other).c_str());
    assert(EC_POINT_mul(curve, point, exp, 0, 0, 0) != 0);
    BN_free(exp);
}

P256Element::~P256Element()
{
    EC_POINT_free(point);
}

P256Element& P256Element::operator =(const P256Element& other)
{
    assert(EC_POINT_copy(point, other.point) != 0);
    return *this;
}

void P256Element::check()
{
    assert(EC_POINT_is_on_curve(curve, point, 0) == 1);
}

P256Element::Scalar P256Element::x() const
{
    BIGNUM* x = BN_new();
#if OPENSSL_VERSION_MAJOR >= 3
    assert(EC_POINT_get_affine_coordinates(curve, point, x, 0, 0) != 0);
#else
    assert(EC_POINT_get_affine_coordinates_GFp(curve, point, x, 0, 0) != 0);
#endif
    char* xx = BN_bn2dec(x);
    Scalar res((bigint(xx)));
    OPENSSL_free(xx);
    BN_free(x);
    return res;
}

P256Element P256Element::operator +(const P256Element& other) const
{
    P256Element res;
    assert(EC_POINT_add(curve, res.point, point, other.point, 0) != 0);
    return res;
}

P256Element P256Element::operator -(const P256Element& other) const
{
    P256Element tmp = other;
    assert(EC_POINT_invert(curve, tmp.point, 0) != 0);
    return *this + tmp;
}

P256Element P256Element::operator *(const Scalar& other) const
{
    P256Element res;
    BIGNUM* exp = BN_new();
    BN_dec2bn(&exp, bigint(other).get_str().c_str());
    assert(EC_POINT_mul(curve, res.point, 0, point, exp, 0) != 0);
    BN_free(exp);
    return res;
}

bool P256Element::operator ==(const P256Element& other) const
{
    int cmp = EC_POINT_cmp(curve, point, other.point, 0);
    assert(cmp == 0 or cmp == 1);
    return not cmp;
}

void P256Element::pack(octetStream& os, int) const
{
    octet* buffer;
    size_t length = EC_POINT_point2buf(curve, point,
            POINT_CONVERSION_COMPRESSED, &buffer, 0);
    assert(length != 0);
    os.store_int(length, 8);
    os.append(buffer, length);
    free(buffer);
}

void P256Element::unpack(octetStream& os, int)
{
    size_t length = os.get_int(8);
    assert(
            EC_POINT_oct2point(curve, point, os.consume(length), length, 0)
                    != 0);
}

ostream& operator <<(ostream& s, const P256Element& x)
{
    char* hex = EC_POINT_point2hex(x.curve, x.point,
            POINT_CONVERSION_COMPRESSED, 0);
    s << hex;
    OPENSSL_free(hex);
    return s;
}

void P256Element::output(ostream& s, bool human) const
{
    assert(human);
    s << *this;
}

P256Element::P256Element(const P256Element& other) :
        P256Element()
{
    *this = other;
}

P256Element operator*(const P256Element::Scalar& x, const P256Element& y)
{
    return y * x;
}

P256Element& P256Element::operator +=(const P256Element& other)
{
    *this = *this + other;
    return *this;
}

P256Element& P256Element::operator *=(const Scalar& other)
{
    *this = *this * other;
    return *this;
}

P256Element& P256Element::operator /=(const Scalar& other)
{
    *this = *this * other.invert();
    return *this;
}

bool P256Element::operator !=(const P256Element& other) const
{
    return not (*this == other);
}
P256Element::Scalar P256Element::rand() const
{
  // Get the order of the secp256k1 curve
    BIGNUM* order = BN_new();
    EC_GROUP_get_order(curve, order, nullptr);
    BIGNUM* k = BN_new();
    BN_rand_range(k, order);
    char* xx = BN_bn2dec(k);
    Scalar res((bigint(xx)));
    OPENSSL_free(xx);
    BN_free(k);
    return res;
}

P256Element::Scalar P256Element::generate_ai(const string& seed, int i)
{

    // Get the order of the secp256k1 curve
    BIGNUM* order = BN_new();
    EC_GROUP_get_order(curve, order, nullptr);

    // Hash generation
    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int hash_len;
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL);

    string data = seed + to_string(i);
    EVP_DigestUpdate(mdctx, data.c_str(), data.length());
    EVP_DigestFinal_ex(mdctx, hash, &hash_len);
    EVP_MD_CTX_free(mdctx);

    // Create a new BIGNUM for result
    BIGNUM* k = BN_new();


    // Create temporary BIGNUM for modulo operation
    BIGNUM* tmp = BN_new();

    // Convert hash to BIGNUM
    BN_bin2bn(hash, hash_len, tmp);

    // Perform modulo operation with proper context
    BN_CTX* ctx = BN_CTX_new();


    // Properly handle the modulo operation
    BN_mod(k, tmp, order, ctx);

    // Convert to decimal string
    char* xx = BN_bn2dec(k);

    // Create scalar from decimal string
    Scalar res((bigint(xx)));

    // Cleanup
    OPENSSL_free(xx);
    BN_CTX_free(ctx);
    BN_free(tmp);
    BN_free(k);
    BN_free(order);

//    cout << "Successfully generated scalar from hash" << endl;
    return res;
}
