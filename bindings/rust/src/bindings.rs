#[cfg(test)]
macro_rules! offsetof {
    ($type:ty, $field:tt) => {
        {
            let v = <$type>::default();
            (&v.$field as *const _ as usize) - (&v as *const _ as usize)
        }
    };
}
/* automatically generated by rust-bindgen 0.59.2 */

#[repr(u32)]
#[derive(Debug, Copy, Clone, Hash, PartialEq, Eq)]
pub enum BLST_ERROR {
    BLST_SUCCESS = 0,
    BLST_BAD_ENCODING = 1,
    BLST_POINT_NOT_ON_CURVE = 2,
    BLST_POINT_NOT_IN_GROUP = 3,
    BLST_AGGR_TYPE_MISMATCH = 4,
    BLST_VERIFY_FAIL = 5,
    BLST_PK_IS_INFINITY = 6,
    BLST_BAD_SCALAR = 7,
}
pub type byte = u8;
pub type limb_t = u64;
#[repr(C)]
#[derive(Debug, Default, Clone, PartialEq, Eq, Zeroize)]
#[zeroize(drop)]
pub struct blst_scalar {
    pub b: [byte; 32usize],
}
#[test]
fn bindgen_test_layout_blst_scalar() {
    assert_eq!(
        ::core::mem::size_of::<blst_scalar>(),
        32usize,
        concat!("Size of: ", stringify!(blst_scalar))
    );
    assert_eq!(
        ::core::mem::align_of::<blst_scalar>(),
        1usize,
        concat!("Alignment of ", stringify!(blst_scalar))
    );
    assert_eq!(
        offsetof!(blst_scalar, b),
        0usize,
        concat!(
            "Offset of field: ",
            stringify!(blst_scalar),
            "::",
            stringify!(b)
        )
    );
}
#[repr(C)]
#[derive(Debug, Default, Copy, Clone, PartialEq, Eq)]
pub struct blst_fr {
    pub l: [limb_t; 4usize],
}
#[test]
fn bindgen_test_layout_blst_fr() {
    assert_eq!(
        ::core::mem::size_of::<blst_fr>(),
        32usize,
        concat!("Size of: ", stringify!(blst_fr))
    );
    assert_eq!(
        ::core::mem::align_of::<blst_fr>(),
        8usize,
        concat!("Alignment of ", stringify!(blst_fr))
    );
    assert_eq!(
        offsetof!(blst_fr, l),
        0usize,
        concat!(
            "Offset of field: ",
            stringify!(blst_fr),
            "::",
            stringify!(l)
        )
    );
}
#[repr(C)]
#[derive(Debug, Default, Copy, Clone, PartialEq, Eq)]
pub struct blst_fp {
    pub l: [limb_t; 6usize],
}
#[test]
fn bindgen_test_layout_blst_fp() {
    assert_eq!(
        ::core::mem::size_of::<blst_fp>(),
        48usize,
        concat!("Size of: ", stringify!(blst_fp))
    );
    assert_eq!(
        ::core::mem::align_of::<blst_fp>(),
        8usize,
        concat!("Alignment of ", stringify!(blst_fp))
    );
    assert_eq!(
        offsetof!(blst_fp, l),
        0usize,
        concat!(
            "Offset of field: ",
            stringify!(blst_fp),
            "::",
            stringify!(l)
        )
    );
}
#[repr(C)]
#[derive(Debug, Default, Copy, Clone, PartialEq, Eq)]
pub struct blst_fp2 {
    pub fp: [blst_fp; 2usize],
}
#[test]
fn bindgen_test_layout_blst_fp2() {
    assert_eq!(
        ::core::mem::size_of::<blst_fp2>(),
        96usize,
        concat!("Size of: ", stringify!(blst_fp2))
    );
    assert_eq!(
        ::core::mem::align_of::<blst_fp2>(),
        8usize,
        concat!("Alignment of ", stringify!(blst_fp2))
    );
    assert_eq!(
        offsetof!(blst_fp2, fp),
        0usize,
        concat!(
            "Offset of field: ",
            stringify!(blst_fp2),
            "::",
            stringify!(fp)
        )
    );
}
#[repr(C)]
#[derive(Debug, Default, Copy, Clone, PartialEq, Eq)]
pub struct blst_fp6 {
    pub fp2: [blst_fp2; 3usize],
}
#[test]
fn bindgen_test_layout_blst_fp6() {
    assert_eq!(
        ::core::mem::size_of::<blst_fp6>(),
        288usize,
        concat!("Size of: ", stringify!(blst_fp6))
    );
    assert_eq!(
        ::core::mem::align_of::<blst_fp6>(),
        8usize,
        concat!("Alignment of ", stringify!(blst_fp6))
    );
    assert_eq!(
        offsetof!(blst_fp6, fp2),
        0usize,
        concat!(
            "Offset of field: ",
            stringify!(blst_fp6),
            "::",
            stringify!(fp2)
        )
    );
}
#[repr(C)]
#[derive(Debug, Copy, Clone, Eq)]
pub struct blst_fp12 {
    pub fp6: [blst_fp6; 2usize],
}
#[test]
fn bindgen_test_layout_blst_fp12() {
    assert_eq!(
        ::core::mem::size_of::<blst_fp12>(),
        576usize,
        concat!("Size of: ", stringify!(blst_fp12))
    );
    assert_eq!(
        ::core::mem::align_of::<blst_fp12>(),
        8usize,
        concat!("Alignment of ", stringify!(blst_fp12))
    );
    assert_eq!(
        offsetof!(blst_fp12, fp6),
        0usize,
        concat!(
            "Offset of field: ",
            stringify!(blst_fp12),
            "::",
            stringify!(fp6)
        )
    );
}
extern "C" {
    pub fn blst_scalar_from_uint32(out: *mut blst_scalar, a: *const u32);
}
extern "C" {
    pub fn blst_uint32_from_scalar(out: *mut u32, a: *const blst_scalar);
}
extern "C" {
    pub fn blst_scalar_from_uint64(out: *mut blst_scalar, a: *const u64);
}
extern "C" {
    pub fn blst_uint64_from_scalar(out: *mut u64, a: *const blst_scalar);
}
extern "C" {
    pub fn blst_scalar_from_bendian(out: *mut blst_scalar, a: *const byte);
}
extern "C" {
    pub fn blst_bendian_from_scalar(out: *mut byte, a: *const blst_scalar);
}
extern "C" {
    pub fn blst_scalar_from_lendian(out: *mut blst_scalar, a: *const byte);
}
extern "C" {
    pub fn blst_lendian_from_scalar(out: *mut byte, a: *const blst_scalar);
}
extern "C" {
    pub fn blst_scalar_fr_check(a: *const blst_scalar) -> bool;
}
extern "C" {
    pub fn blst_sk_check(a: *const blst_scalar) -> bool;
}
extern "C" {
    pub fn blst_sk_add_n_check(
        out: *mut blst_scalar,
        a: *const blst_scalar,
        b: *const blst_scalar,
    ) -> bool;
}
extern "C" {
    pub fn blst_sk_sub_n_check(
        out: *mut blst_scalar,
        a: *const blst_scalar,
        b: *const blst_scalar,
    ) -> bool;
}
extern "C" {
    pub fn blst_sk_mul_n_check(
        out: *mut blst_scalar,
        a: *const blst_scalar,
        b: *const blst_scalar,
    ) -> bool;
}
extern "C" {
    pub fn blst_sk_inverse(out: *mut blst_scalar, a: *const blst_scalar);
}
extern "C" {
    pub fn blst_scalar_from_le_bytes(out: *mut blst_scalar, in_: *const byte, len: usize) -> bool;
}
extern "C" {
    pub fn blst_scalar_from_be_bytes(out: *mut blst_scalar, in_: *const byte, len: usize) -> bool;
}
extern "C" {
    pub fn blst_fr_add(ret: *mut blst_fr, a: *const blst_fr, b: *const blst_fr);
}
extern "C" {
    pub fn blst_fr_sub(ret: *mut blst_fr, a: *const blst_fr, b: *const blst_fr);
}
extern "C" {
    pub fn blst_fr_mul_by_3(ret: *mut blst_fr, a: *const blst_fr);
}
extern "C" {
    pub fn blst_fr_lshift(ret: *mut blst_fr, a: *const blst_fr, count: usize);
}
extern "C" {
    pub fn blst_fr_rshift(ret: *mut blst_fr, a: *const blst_fr, count: usize);
}
extern "C" {
    pub fn blst_fr_mul(ret: *mut blst_fr, a: *const blst_fr, b: *const blst_fr);
}
extern "C" {
    pub fn blst_fr_sqr(ret: *mut blst_fr, a: *const blst_fr);
}
extern "C" {
    pub fn blst_fr_cneg(ret: *mut blst_fr, a: *const blst_fr, flag: bool);
}
extern "C" {
    pub fn blst_fr_eucl_inverse(ret: *mut blst_fr, a: *const blst_fr);
}
extern "C" {
    pub fn blst_fr_inverse(ret: *mut blst_fr, a: *const blst_fr);
}
extern "C" {
    pub fn blst_fr_from_uint64(ret: *mut blst_fr, a: *const u64);
}
extern "C" {
    pub fn blst_uint64_from_fr(ret: *mut u64, a: *const blst_fr);
}
extern "C" {
    pub fn blst_fr_from_scalar(ret: *mut blst_fr, a: *const blst_scalar);
}
extern "C" {
    pub fn blst_scalar_from_fr(ret: *mut blst_scalar, a: *const blst_fr);
}
extern "C" {
    pub fn blst_fp_add(ret: *mut blst_fp, a: *const blst_fp, b: *const blst_fp);
}
extern "C" {
    pub fn blst_fp_sub(ret: *mut blst_fp, a: *const blst_fp, b: *const blst_fp);
}
extern "C" {
    pub fn blst_fp_mul_by_3(ret: *mut blst_fp, a: *const blst_fp);
}
extern "C" {
    pub fn blst_fp_mul_by_8(ret: *mut blst_fp, a: *const blst_fp);
}
extern "C" {
    pub fn blst_fp_lshift(ret: *mut blst_fp, a: *const blst_fp, count: usize);
}
extern "C" {
    pub fn blst_fp_mul(ret: *mut blst_fp, a: *const blst_fp, b: *const blst_fp);
}
extern "C" {
    pub fn blst_fp_sqr(ret: *mut blst_fp, a: *const blst_fp);
}
extern "C" {
    pub fn blst_fp_cneg(ret: *mut blst_fp, a: *const blst_fp, flag: bool);
}
extern "C" {
    pub fn blst_fp_eucl_inverse(ret: *mut blst_fp, a: *const blst_fp);
}
extern "C" {
    pub fn blst_fp_inverse(ret: *mut blst_fp, a: *const blst_fp);
}
extern "C" {
    pub fn blst_fp_sqrt(ret: *mut blst_fp, a: *const blst_fp) -> bool;
}
extern "C" {
    pub fn blst_fp_from_uint32(ret: *mut blst_fp, a: *const u32);
}
extern "C" {
    pub fn blst_uint32_from_fp(ret: *mut u32, a: *const blst_fp);
}
extern "C" {
    pub fn blst_fp_from_uint64(ret: *mut blst_fp, a: *const u64);
}
extern "C" {
    pub fn blst_uint64_from_fp(ret: *mut u64, a: *const blst_fp);
}
extern "C" {
    pub fn blst_fp_from_bendian(ret: *mut blst_fp, a: *const byte);
}
extern "C" {
    pub fn blst_bendian_from_fp(ret: *mut byte, a: *const blst_fp);
}
extern "C" {
    pub fn blst_fp_from_lendian(ret: *mut blst_fp, a: *const byte);
}
extern "C" {
    pub fn blst_lendian_from_fp(ret: *mut byte, a: *const blst_fp);
}
extern "C" {
    pub fn blst_fp2_add(ret: *mut blst_fp2, a: *const blst_fp2, b: *const blst_fp2);
}
extern "C" {
    pub fn blst_fp2_sub(ret: *mut blst_fp2, a: *const blst_fp2, b: *const blst_fp2);
}
extern "C" {
    pub fn blst_fp2_mul_by_3(ret: *mut blst_fp2, a: *const blst_fp2);
}
extern "C" {
    pub fn blst_fp2_mul_by_8(ret: *mut blst_fp2, a: *const blst_fp2);
}
extern "C" {
    pub fn blst_fp2_lshift(ret: *mut blst_fp2, a: *const blst_fp2, count: usize);
}
extern "C" {
    pub fn blst_fp2_mul(ret: *mut blst_fp2, a: *const blst_fp2, b: *const blst_fp2);
}
extern "C" {
    pub fn blst_fp2_sqr(ret: *mut blst_fp2, a: *const blst_fp2);
}
extern "C" {
    pub fn blst_fp2_cneg(ret: *mut blst_fp2, a: *const blst_fp2, flag: bool);
}
extern "C" {
    pub fn blst_fp2_eucl_inverse(ret: *mut blst_fp2, a: *const blst_fp2);
}
extern "C" {
    pub fn blst_fp2_inverse(ret: *mut blst_fp2, a: *const blst_fp2);
}
extern "C" {
    pub fn blst_fp2_sqrt(ret: *mut blst_fp2, a: *const blst_fp2) -> bool;
}
extern "C" {
    pub fn blst_fp12_sqr(ret: *mut blst_fp12, a: *const blst_fp12);
}
extern "C" {
    pub fn blst_fp12_cyclotomic_sqr(ret: *mut blst_fp12, a: *const blst_fp12);
}
extern "C" {
    pub fn blst_fp12_mul(ret: *mut blst_fp12, a: *const blst_fp12, b: *const blst_fp12);
}
extern "C" {
    pub fn blst_fp12_mul_by_xy00z0(
        ret: *mut blst_fp12,
        a: *const blst_fp12,
        xy00z0: *const blst_fp6,
    );
}
extern "C" {
    pub fn blst_fp12_conjugate(a: *mut blst_fp12);
}
extern "C" {
    pub fn blst_fp12_inverse(ret: *mut blst_fp12, a: *const blst_fp12);
}
extern "C" {
    pub fn blst_fp12_frobenius_map(ret: *mut blst_fp12, a: *const blst_fp12, n: usize);
}
extern "C" {
    pub fn blst_fp12_is_equal(a: *const blst_fp12, b: *const blst_fp12) -> bool;
}
extern "C" {
    pub fn blst_fp12_is_one(a: *const blst_fp12) -> bool;
}
extern "C" {
    pub fn blst_fp12_in_group(a: *const blst_fp12) -> bool;
}
extern "C" {
    pub fn blst_fp12_one() -> *const blst_fp12;
}
#[repr(C)]
#[derive(Debug, Default, Copy, Clone, Eq)]
pub struct blst_p1 {
    pub x: blst_fp,
    pub y: blst_fp,
    pub z: blst_fp,
}
#[test]
fn bindgen_test_layout_blst_p1() {
    assert_eq!(
        ::core::mem::size_of::<blst_p1>(),
        144usize,
        concat!("Size of: ", stringify!(blst_p1))
    );
    assert_eq!(
        ::core::mem::align_of::<blst_p1>(),
        8usize,
        concat!("Alignment of ", stringify!(blst_p1))
    );
    assert_eq!(
        offsetof!(blst_p1, x),
        0usize,
        concat!(
            "Offset of field: ",
            stringify!(blst_p1),
            "::",
            stringify!(x)
        )
    );
    assert_eq!(
        offsetof!(blst_p1, y),
        48usize,
        concat!(
            "Offset of field: ",
            stringify!(blst_p1),
            "::",
            stringify!(y)
        )
    );
    assert_eq!(
        offsetof!(blst_p1, z),
        96usize,
        concat!(
            "Offset of field: ",
            stringify!(blst_p1),
            "::",
            stringify!(z)
        )
    );
}
#[repr(C)]
#[derive(Debug, Default, Copy, Clone, Eq)]
pub struct blst_p1_affine {
    pub x: blst_fp,
    pub y: blst_fp,
}
#[test]
fn bindgen_test_layout_blst_p1_affine() {
    assert_eq!(
        ::core::mem::size_of::<blst_p1_affine>(),
        96usize,
        concat!("Size of: ", stringify!(blst_p1_affine))
    );
    assert_eq!(
        ::core::mem::align_of::<blst_p1_affine>(),
        8usize,
        concat!("Alignment of ", stringify!(blst_p1_affine))
    );
    assert_eq!(
        offsetof!(blst_p1_affine, x),
        0usize,
        concat!(
            "Offset of field: ",
            stringify!(blst_p1_affine),
            "::",
            stringify!(x)
        )
    );
    assert_eq!(
        offsetof!(blst_p1_affine, y),
        48usize,
        concat!(
            "Offset of field: ",
            stringify!(blst_p1_affine),
            "::",
            stringify!(y)
        )
    );
}
extern "C" {
    pub fn blst_p1_add(out: *mut blst_p1, a: *const blst_p1, b: *const blst_p1);
}
extern "C" {
    pub fn blst_p1_add_or_double(out: *mut blst_p1, a: *const blst_p1, b: *const blst_p1);
}
extern "C" {
    pub fn blst_p1_add_affine(out: *mut blst_p1, a: *const blst_p1, b: *const blst_p1_affine);
}
extern "C" {
    pub fn blst_p1_add_or_double_affine(
        out: *mut blst_p1,
        a: *const blst_p1,
        b: *const blst_p1_affine,
    );
}
extern "C" {
    pub fn blst_p1_double(out: *mut blst_p1, a: *const blst_p1);
}
extern "C" {
    pub fn blst_p1_mult(out: *mut blst_p1, p: *const blst_p1, scalar: *const byte, nbits: usize);
}
extern "C" {
    pub fn blst_p1_cneg(p: *mut blst_p1, cbit: bool);
}
extern "C" {
    pub fn blst_p1_to_affine(out: *mut blst_p1_affine, in_: *const blst_p1);
}
extern "C" {
    pub fn blst_p1_from_affine(out: *mut blst_p1, in_: *const blst_p1_affine);
}
extern "C" {
    pub fn blst_p1_on_curve(p: *const blst_p1) -> bool;
}
extern "C" {
    pub fn blst_p1_in_g1(p: *const blst_p1) -> bool;
}
extern "C" {
    pub fn blst_p1_is_equal(a: *const blst_p1, b: *const blst_p1) -> bool;
}
extern "C" {
    pub fn blst_p1_is_inf(a: *const blst_p1) -> bool;
}
extern "C" {
    pub fn blst_p1_generator() -> *const blst_p1;
}
extern "C" {
    pub fn blst_p1_affine_on_curve(p: *const blst_p1_affine) -> bool;
}
extern "C" {
    pub fn blst_p1_affine_in_g1(p: *const blst_p1_affine) -> bool;
}
extern "C" {
    pub fn blst_p1_affine_is_equal(a: *const blst_p1_affine, b: *const blst_p1_affine) -> bool;
}
extern "C" {
    pub fn blst_p1_affine_is_inf(a: *const blst_p1_affine) -> bool;
}
extern "C" {
    pub fn blst_p1_affine_generator() -> *const blst_p1_affine;
}
#[repr(C)]
#[derive(Debug, Default, Copy, Clone, Eq)]
pub struct blst_p2 {
    pub x: blst_fp2,
    pub y: blst_fp2,
    pub z: blst_fp2,
}
#[test]
fn bindgen_test_layout_blst_p2() {
    assert_eq!(
        ::core::mem::size_of::<blst_p2>(),
        288usize,
        concat!("Size of: ", stringify!(blst_p2))
    );
    assert_eq!(
        ::core::mem::align_of::<blst_p2>(),
        8usize,
        concat!("Alignment of ", stringify!(blst_p2))
    );
    assert_eq!(
        offsetof!(blst_p2, x),
        0usize,
        concat!(
            "Offset of field: ",
            stringify!(blst_p2),
            "::",
            stringify!(x)
        )
    );
    assert_eq!(
        offsetof!(blst_p2, y),
        96usize,
        concat!(
            "Offset of field: ",
            stringify!(blst_p2),
            "::",
            stringify!(y)
        )
    );
    assert_eq!(
        offsetof!(blst_p2, z),
        192usize,
        concat!(
            "Offset of field: ",
            stringify!(blst_p2),
            "::",
            stringify!(z)
        )
    );
}
#[repr(C)]
#[derive(Debug, Default, Copy, Clone, Eq)]
pub struct blst_p2_affine {
    pub x: blst_fp2,
    pub y: blst_fp2,
}
#[test]
fn bindgen_test_layout_blst_p2_affine() {
    assert_eq!(
        ::core::mem::size_of::<blst_p2_affine>(),
        192usize,
        concat!("Size of: ", stringify!(blst_p2_affine))
    );
    assert_eq!(
        ::core::mem::align_of::<blst_p2_affine>(),
        8usize,
        concat!("Alignment of ", stringify!(blst_p2_affine))
    );
    assert_eq!(
        offsetof!(blst_p2_affine, x),
        0usize,
        concat!(
            "Offset of field: ",
            stringify!(blst_p2_affine),
            "::",
            stringify!(x)
        )
    );
    assert_eq!(
        offsetof!(blst_p2_affine, y),
        96usize,
        concat!(
            "Offset of field: ",
            stringify!(blst_p2_affine),
            "::",
            stringify!(y)
        )
    );
}
extern "C" {
    pub fn blst_p2_add(out: *mut blst_p2, a: *const blst_p2, b: *const blst_p2);
}
extern "C" {
    pub fn blst_p2_add_or_double(out: *mut blst_p2, a: *const blst_p2, b: *const blst_p2);
}
extern "C" {
    pub fn blst_p2_add_affine(out: *mut blst_p2, a: *const blst_p2, b: *const blst_p2_affine);
}
extern "C" {
    pub fn blst_p2_add_or_double_affine(
        out: *mut blst_p2,
        a: *const blst_p2,
        b: *const blst_p2_affine,
    );
}
extern "C" {
    pub fn blst_p2_double(out: *mut blst_p2, a: *const blst_p2);
}
extern "C" {
    pub fn blst_p2_mult(out: *mut blst_p2, p: *const blst_p2, scalar: *const byte, nbits: usize);
}
extern "C" {
    pub fn blst_p2_cneg(p: *mut blst_p2, cbit: bool);
}
extern "C" {
    pub fn blst_p2_to_affine(out: *mut blst_p2_affine, in_: *const blst_p2);
}
extern "C" {
    pub fn blst_p2_from_affine(out: *mut blst_p2, in_: *const blst_p2_affine);
}
extern "C" {
    pub fn blst_p2_on_curve(p: *const blst_p2) -> bool;
}
extern "C" {
    pub fn blst_p2_in_g2(p: *const blst_p2) -> bool;
}
extern "C" {
    pub fn blst_p2_is_equal(a: *const blst_p2, b: *const blst_p2) -> bool;
}
extern "C" {
    pub fn blst_p2_is_inf(a: *const blst_p2) -> bool;
}
extern "C" {
    pub fn blst_p2_generator() -> *const blst_p2;
}
extern "C" {
    pub fn blst_p2_affine_on_curve(p: *const blst_p2_affine) -> bool;
}
extern "C" {
    pub fn blst_p2_affine_in_g2(p: *const blst_p2_affine) -> bool;
}
extern "C" {
    pub fn blst_p2_affine_is_equal(a: *const blst_p2_affine, b: *const blst_p2_affine) -> bool;
}
extern "C" {
    pub fn blst_p2_affine_is_inf(a: *const blst_p2_affine) -> bool;
}
extern "C" {
    pub fn blst_p2_affine_generator() -> *const blst_p2_affine;
}
extern "C" {
    pub fn blst_p1s_to_affine(
        dst: *mut blst_p1_affine,
        points: *const *const blst_p1,
        npoints: usize,
    );
}
extern "C" {
    pub fn blst_p1s_add(ret: *mut blst_p1, points: *const *const blst_p1_affine, npoints: usize);
}
extern "C" {
    pub fn blst_p1s_mult_wbits_precompute_sizeof(wbits: usize, npoints: usize) -> usize;
}
extern "C" {
    pub fn blst_p1s_mult_wbits_precompute(
        table: *mut blst_p1_affine,
        wbits: usize,
        points: *const *const blst_p1_affine,
        npoints: usize,
    );
}
extern "C" {
    pub fn blst_p1s_mult_wbits_scratch_sizeof(npoints: usize) -> usize;
}
extern "C" {
    pub fn blst_p1s_mult_wbits(
        ret: *mut blst_p1,
        table: *const blst_p1_affine,
        wbits: usize,
        npoints: usize,
        scalars: *const *const byte,
        nbits: usize,
        scratch: *mut limb_t,
    );
}
extern "C" {
    pub fn blst_p1s_mult_pippenger_scratch_sizeof(npoints: usize) -> usize;
}
extern "C" {
    pub fn blst_p1s_mult_pippenger(
        ret: *mut blst_p1,
        points: *const *const blst_p1_affine,
        npoints: usize,
        scalars: *const *const byte,
        nbits: usize,
        scratch: *mut limb_t,
    );
}
extern "C" {
    pub fn blst_p1s_tile_pippenger(
        ret: *mut blst_p1,
        points: *const *const blst_p1_affine,
        npoints: usize,
        scalars: *const *const byte,
        nbits: usize,
        scratch: *mut limb_t,
        bit0: usize,
        window: usize,
    );
}
extern "C" {
    pub fn blst_p2s_to_affine(
        dst: *mut blst_p2_affine,
        points: *const *const blst_p2,
        npoints: usize,
    );
}
extern "C" {
    pub fn blst_p2s_add(ret: *mut blst_p2, points: *const *const blst_p2_affine, npoints: usize);
}
extern "C" {
    pub fn blst_p2s_mult_wbits_precompute_sizeof(wbits: usize, npoints: usize) -> usize;
}
extern "C" {
    pub fn blst_p2s_mult_wbits_precompute(
        table: *mut blst_p2_affine,
        wbits: usize,
        points: *const *const blst_p2_affine,
        npoints: usize,
    );
}
extern "C" {
    pub fn blst_p2s_mult_wbits_scratch_sizeof(npoints: usize) -> usize;
}
extern "C" {
    pub fn blst_p2s_mult_wbits(
        ret: *mut blst_p2,
        table: *const blst_p2_affine,
        wbits: usize,
        npoints: usize,
        scalars: *const *const byte,
        nbits: usize,
        scratch: *mut limb_t,
    );
}
extern "C" {
    pub fn blst_p2s_mult_pippenger_scratch_sizeof(npoints: usize) -> usize;
}
extern "C" {
    pub fn blst_p2s_mult_pippenger(
        ret: *mut blst_p2,
        points: *const *const blst_p2_affine,
        npoints: usize,
        scalars: *const *const byte,
        nbits: usize,
        scratch: *mut limb_t,
    );
}
extern "C" {
    pub fn blst_p2s_tile_pippenger(
        ret: *mut blst_p2,
        points: *const *const blst_p2_affine,
        npoints: usize,
        scalars: *const *const byte,
        nbits: usize,
        scratch: *mut limb_t,
        bit0: usize,
        window: usize,
    );
}
extern "C" {
    pub fn blst_map_to_g1(out: *mut blst_p1, u: *const blst_fp, v: *const blst_fp);
}
extern "C" {
    pub fn blst_map_to_g2(out: *mut blst_p2, u: *const blst_fp2, v: *const blst_fp2);
}
extern "C" {
    pub fn blst_encode_to_g1(
        out: *mut blst_p1,
        msg: *const byte,
        msg_len: usize,
        DST: *const byte,
        DST_len: usize,
        aug: *const byte,
        aug_len: usize,
    );
}
extern "C" {
    pub fn blst_hash_to_g1(
        out: *mut blst_p1,
        msg: *const byte,
        msg_len: usize,
        DST: *const byte,
        DST_len: usize,
        aug: *const byte,
        aug_len: usize,
    );
}
extern "C" {
    pub fn blst_encode_to_g2(
        out: *mut blst_p2,
        msg: *const byte,
        msg_len: usize,
        DST: *const byte,
        DST_len: usize,
        aug: *const byte,
        aug_len: usize,
    );
}
extern "C" {
    pub fn blst_hash_to_g2(
        out: *mut blst_p2,
        msg: *const byte,
        msg_len: usize,
        DST: *const byte,
        DST_len: usize,
        aug: *const byte,
        aug_len: usize,
    );
}
extern "C" {
    pub fn blst_p1_serialize(out: *mut byte, in_: *const blst_p1);
}
extern "C" {
    pub fn blst_p1_compress(out: *mut byte, in_: *const blst_p1);
}
extern "C" {
    pub fn blst_p1_affine_serialize(out: *mut byte, in_: *const blst_p1_affine);
}
extern "C" {
    pub fn blst_p1_affine_compress(out: *mut byte, in_: *const blst_p1_affine);
}
extern "C" {
    pub fn blst_p1_uncompress(out: *mut blst_p1_affine, in_: *const byte) -> BLST_ERROR;
}
extern "C" {
    pub fn blst_p1_deserialize(out: *mut blst_p1_affine, in_: *const byte) -> BLST_ERROR;
}
extern "C" {
    pub fn blst_p2_serialize(out: *mut byte, in_: *const blst_p2);
}
extern "C" {
    pub fn blst_p2_compress(out: *mut byte, in_: *const blst_p2);
}
extern "C" {
    pub fn blst_p2_affine_serialize(out: *mut byte, in_: *const blst_p2_affine);
}
extern "C" {
    pub fn blst_p2_affine_compress(out: *mut byte, in_: *const blst_p2_affine);
}
extern "C" {
    pub fn blst_p2_uncompress(out: *mut blst_p2_affine, in_: *const byte) -> BLST_ERROR;
}
extern "C" {
    pub fn blst_p2_deserialize(out: *mut blst_p2_affine, in_: *const byte) -> BLST_ERROR;
}
extern "C" {
    pub fn blst_keygen(
        out_SK: *mut blst_scalar,
        IKM: *const byte,
        IKM_len: usize,
        info: *const byte,
        info_len: usize,
    );
}
extern "C" {
    pub fn blst_sk_to_pk_in_g1(out_pk: *mut blst_p1, SK: *const blst_scalar);
}
extern "C" {
    pub fn blst_sign_pk_in_g1(out_sig: *mut blst_p2, hash: *const blst_p2, SK: *const blst_scalar);
}
extern "C" {
    pub fn blst_sk_to_pk_in_g2(out_pk: *mut blst_p2, SK: *const blst_scalar);
}
extern "C" {
    pub fn blst_sign_pk_in_g2(out_sig: *mut blst_p1, hash: *const blst_p1, SK: *const blst_scalar);
}
extern "C" {
    pub fn blst_miller_loop(
        ret: *mut blst_fp12,
        Q: *const blst_p2_affine,
        P: *const blst_p1_affine,
    );
}
extern "C" {
    pub fn blst_miller_loop_n(
        ret: *mut blst_fp12,
        Qs: *const *const blst_p2_affine,
        Ps: *const *const blst_p1_affine,
        n: usize,
    );
}
extern "C" {
    pub fn blst_final_exp(ret: *mut blst_fp12, f: *const blst_fp12);
}
extern "C" {
    pub fn blst_precompute_lines(Qlines: *mut blst_fp6, Q: *const blst_p2_affine);
}
extern "C" {
    pub fn blst_miller_loop_lines(
        ret: *mut blst_fp12,
        Qlines: *const blst_fp6,
        P: *const blst_p1_affine,
    );
}
extern "C" {
    pub fn blst_fp12_finalverify(gt1: *const blst_fp12, gt2: *const blst_fp12) -> bool;
}
#[repr(C)]
#[repr(align(1))]
#[derive(Debug, Default)]
pub struct blst_pairing {
    pub _bindgen_opaque_blob: [u8; 0usize],
}
#[test]
fn bindgen_test_layout_blst_pairing() {
    assert_eq!(
        ::core::mem::size_of::<blst_pairing>(),
        0usize,
        concat!("Size of: ", stringify!(blst_pairing))
    );
    assert_eq!(
        ::core::mem::align_of::<blst_pairing>(),
        1usize,
        concat!("Alignment of ", stringify!(blst_pairing))
    );
}
extern "C" {
    pub fn blst_pairing_sizeof() -> usize;
}
extern "C" {
    pub fn blst_pairing_init(
        new_ctx: *mut blst_pairing,
        hash_or_encode: bool,
        DST: *const byte,
        DST_len: usize,
    );
}
extern "C" {
    pub fn blst_pairing_get_dst(ctx: *const blst_pairing) -> *const byte;
}
extern "C" {
    pub fn blst_pairing_commit(ctx: *mut blst_pairing);
}
extern "C" {
    pub fn blst_pairing_aggregate_pk_in_g2(
        ctx: *mut blst_pairing,
        PK: *const blst_p2_affine,
        signature: *const blst_p1_affine,
        msg: *const byte,
        msg_len: usize,
        aug: *const byte,
        aug_len: usize,
    ) -> BLST_ERROR;
}
extern "C" {
    pub fn blst_pairing_chk_n_aggr_pk_in_g2(
        ctx: *mut blst_pairing,
        PK: *const blst_p2_affine,
        pk_grpchk: bool,
        signature: *const blst_p1_affine,
        sig_grpchk: bool,
        msg: *const byte,
        msg_len: usize,
        aug: *const byte,
        aug_len: usize,
    ) -> BLST_ERROR;
}
extern "C" {
    pub fn blst_pairing_mul_n_aggregate_pk_in_g2(
        ctx: *mut blst_pairing,
        PK: *const blst_p2_affine,
        sig: *const blst_p1_affine,
        scalar: *const byte,
        nbits: usize,
        msg: *const byte,
        msg_len: usize,
        aug: *const byte,
        aug_len: usize,
    ) -> BLST_ERROR;
}
extern "C" {
    pub fn blst_pairing_chk_n_mul_n_aggr_pk_in_g2(
        ctx: *mut blst_pairing,
        PK: *const blst_p2_affine,
        pk_grpchk: bool,
        sig: *const blst_p1_affine,
        sig_grpchk: bool,
        scalar: *const byte,
        nbits: usize,
        msg: *const byte,
        msg_len: usize,
        aug: *const byte,
        aug_len: usize,
    ) -> BLST_ERROR;
}
extern "C" {
    pub fn blst_pairing_aggregate_pk_in_g1(
        ctx: *mut blst_pairing,
        PK: *const blst_p1_affine,
        signature: *const blst_p2_affine,
        msg: *const byte,
        msg_len: usize,
        aug: *const byte,
        aug_len: usize,
    ) -> BLST_ERROR;
}
extern "C" {
    pub fn blst_pairing_chk_n_aggr_pk_in_g1(
        ctx: *mut blst_pairing,
        PK: *const blst_p1_affine,
        pk_grpchk: bool,
        signature: *const blst_p2_affine,
        sig_grpchk: bool,
        msg: *const byte,
        msg_len: usize,
        aug: *const byte,
        aug_len: usize,
    ) -> BLST_ERROR;
}
extern "C" {
    pub fn blst_pairing_mul_n_aggregate_pk_in_g1(
        ctx: *mut blst_pairing,
        PK: *const blst_p1_affine,
        sig: *const blst_p2_affine,
        scalar: *const byte,
        nbits: usize,
        msg: *const byte,
        msg_len: usize,
        aug: *const byte,
        aug_len: usize,
    ) -> BLST_ERROR;
}
extern "C" {
    pub fn blst_pairing_chk_n_mul_n_aggr_pk_in_g1(
        ctx: *mut blst_pairing,
        PK: *const blst_p1_affine,
        pk_grpchk: bool,
        sig: *const blst_p2_affine,
        sig_grpchk: bool,
        scalar: *const byte,
        nbits: usize,
        msg: *const byte,
        msg_len: usize,
        aug: *const byte,
        aug_len: usize,
    ) -> BLST_ERROR;
}
extern "C" {
    pub fn blst_pairing_merge(ctx: *mut blst_pairing, ctx1: *const blst_pairing) -> BLST_ERROR;
}
extern "C" {
    pub fn blst_pairing_finalverify(ctx: *const blst_pairing, gtsig: *const blst_fp12) -> bool;
}
extern "C" {
    pub fn blst_aggregate_in_g1(
        out: *mut blst_p1,
        in_: *const blst_p1,
        zwire: *const byte,
    ) -> BLST_ERROR;
}
extern "C" {
    pub fn blst_aggregate_in_g2(
        out: *mut blst_p2,
        in_: *const blst_p2,
        zwire: *const byte,
    ) -> BLST_ERROR;
}
extern "C" {
    pub fn blst_aggregated_in_g1(out: *mut blst_fp12, signature: *const blst_p1_affine);
}
extern "C" {
    pub fn blst_aggregated_in_g2(out: *mut blst_fp12, signature: *const blst_p2_affine);
}
extern "C" {
    pub fn blst_core_verify_pk_in_g1(
        pk: *const blst_p1_affine,
        signature: *const blst_p2_affine,
        hash_or_encode: bool,
        msg: *const byte,
        msg_len: usize,
        DST: *const byte,
        DST_len: usize,
        aug: *const byte,
        aug_len: usize,
    ) -> BLST_ERROR;
}
extern "C" {
    pub fn blst_core_verify_pk_in_g2(
        pk: *const blst_p2_affine,
        signature: *const blst_p1_affine,
        hash_or_encode: bool,
        msg: *const byte,
        msg_len: usize,
        DST: *const byte,
        DST_len: usize,
        aug: *const byte,
        aug_len: usize,
    ) -> BLST_ERROR;
}
extern "C" {
    pub static BLS12_381_G1: blst_p1_affine;
}
extern "C" {
    pub static BLS12_381_NEG_G1: blst_p1_affine;
}
extern "C" {
    pub static BLS12_381_G2: blst_p2_affine;
}
extern "C" {
    pub static BLS12_381_NEG_G2: blst_p2_affine;
}
extern "C" {
    pub fn blst_fr_to(ret: *mut blst_fr, a: *const blst_fr);
}
extern "C" {
    pub fn blst_fr_from(ret: *mut blst_fr, a: *const blst_fr);
}
extern "C" {
    pub fn blst_fp_to(ret: *mut blst_fp, a: *const blst_fp);
}
extern "C" {
    pub fn blst_fp_from(ret: *mut blst_fp, a: *const blst_fp);
}
extern "C" {
    pub fn blst_fp_is_square(a: *const blst_fp) -> bool;
}
extern "C" {
    pub fn blst_fp2_is_square(a: *const blst_fp2) -> bool;
}
extern "C" {
    pub fn blst_p1_from_jacobian(out: *mut blst_p1, in_: *const blst_p1);
}
extern "C" {
    pub fn blst_p2_from_jacobian(out: *mut blst_p2, in_: *const blst_p2);
}
extern "C" {
    pub fn blst_sk_to_pk2_in_g1(
        out: *mut byte,
        out_pk: *mut blst_p1_affine,
        SK: *const blst_scalar,
    );
}
extern "C" {
    pub fn blst_sign_pk2_in_g1(
        out: *mut byte,
        out_sig: *mut blst_p2_affine,
        hash: *const blst_p2,
        SK: *const blst_scalar,
    );
}
extern "C" {
    pub fn blst_sk_to_pk2_in_g2(
        out: *mut byte,
        out_pk: *mut blst_p2_affine,
        SK: *const blst_scalar,
    );
}
extern "C" {
    pub fn blst_sign_pk2_in_g2(
        out: *mut byte,
        out_sig: *mut blst_p1_affine,
        hash: *const blst_p1,
        SK: *const blst_scalar,
    );
}
#[repr(C)]
#[repr(align(1))]
#[derive(Debug, Default)]
pub struct blst_uniq {
    pub _bindgen_opaque_blob: [u8; 0usize],
}
#[test]
fn bindgen_test_layout_blst_uniq() {
    assert_eq!(
        ::core::mem::size_of::<blst_uniq>(),
        0usize,
        concat!("Size of: ", stringify!(blst_uniq))
    );
    assert_eq!(
        ::core::mem::align_of::<blst_uniq>(),
        1usize,
        concat!("Alignment of ", stringify!(blst_uniq))
    );
}
extern "C" {
    pub fn blst_uniq_sizeof(n_nodes: usize) -> usize;
}
extern "C" {
    pub fn blst_uniq_init(tree: *mut blst_uniq);
}
extern "C" {
    pub fn blst_uniq_test(tree: *mut blst_uniq, msg: *const byte, len: usize) -> bool;
}
extern "C" {
    pub fn blst_expand_message_xmd(
        out: *mut byte,
        out_len: usize,
        msg: *const byte,
        msg_len: usize,
        DST: *const byte,
        DST_len: usize,
    );
}
extern "C" {
    pub fn blst_p1_unchecked_mult(
        out: *mut blst_p1,
        p: *const blst_p1,
        scalar: *const byte,
        nbits: usize,
    );
}
extern "C" {
    pub fn blst_p2_unchecked_mult(
        out: *mut blst_p2,
        p: *const blst_p2,
        scalar: *const byte,
        nbits: usize,
    );
}
extern "C" {
    pub fn blst_pairing_raw_aggregate(
        ctx: *mut blst_pairing,
        q: *const blst_p2_affine,
        p: *const blst_p1_affine,
    );
}
extern "C" {
    pub fn blst_pairing_as_fp12(ctx: *mut blst_pairing) -> *mut blst_fp12;
}
extern "C" {
    pub fn blst_bendian_from_fp12(out: *mut byte, a: *const blst_fp12);
}
extern "C" {
    pub fn blst_keygen_v3(
        out_SK: *mut blst_scalar,
        IKM: *const byte,
        IKM_len: usize,
        info: *const byte,
        info_len: usize,
    );
}
extern "C" {
    pub fn blst_keygen_v4_5(
        out_SK: *mut blst_scalar,
        IKM: *const byte,
        IKM_len: usize,
        salt: *const byte,
        salt_len: usize,
        info: *const byte,
        info_len: usize,
    );
}
extern "C" {
    pub fn blst_keygen_v5(
        out_SK: *mut blst_scalar,
        IKM: *const byte,
        IKM_len: usize,
        salt: *const byte,
        salt_len: usize,
        info: *const byte,
        info_len: usize,
    );
}
extern "C" {
    pub fn blst_derive_master_eip2333(out_SK: *mut blst_scalar, IKM: *const byte, IKM_len: usize);
}
extern "C" {
    pub fn blst_derive_child_eip2333(
        out_SK: *mut blst_scalar,
        SK: *const blst_scalar,
        child_index: u32,
    );
}
extern "C" {
    pub fn blst_scalar_from_hexascii(out: *mut blst_scalar, hex: *const byte);
}
extern "C" {
    pub fn blst_fr_from_hexascii(ret: *mut blst_fr, hex: *const byte);
}
extern "C" {
    pub fn blst_fp_from_hexascii(ret: *mut blst_fp, hex: *const byte);
}
extern "C" {
    pub fn blst_p1_sizeof() -> usize;
}
extern "C" {
    pub fn blst_p1_affine_sizeof() -> usize;
}
extern "C" {
    pub fn blst_p2_sizeof() -> usize;
}
extern "C" {
    pub fn blst_p2_affine_sizeof() -> usize;
}
extern "C" {
    pub fn blst_fp12_sizeof() -> usize;
}
extern "C" {
    pub fn blst_sha256(out: *mut byte, msg: *const byte, msg_len: usize);
}
