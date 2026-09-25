use std::fs::{self, File};
use std::path::Path;

use image::codecs::jpeg::JpegEncoder;
use image::{DynamicImage, GrayImage, ImageEncoder, ImageFormat, Luma, Rgba, RgbaImage};
use qrcode::QrCode;
use tempfile::tempdir;
use totp_cli::enrollment::Algorithm;
use totp_cli::qr::read_enrollment;

const RFC_SECRET: &str = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
const ENROLLMENT_URI: &str = "otpauth://totp/Example:alice%40example.com?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&issuer=Example";
const SECOND_URI: &str = "otpauth://totp/Example:bob%40example.com?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&issuer=Example";
const MAX_FILE_BYTES: u64 = 20 * 1024 * 1024;

fn qr_image(payload: &str) -> GrayImage {
    QrCode::new(payload.as_bytes())
        .expect("public fixture must fit in a QR code")
        .render::<Luma<u8>>()
        .module_dimensions(6, 6)
        .build()
}

fn assert_enrollment(path: &Path) {
    let enrollment = match read_enrollment(path) {
        Ok(enrollment) => enrollment,
        Err(_) => panic!("expected the public RFC enrollment fixture to import"),
    };
    assert_eq!(enrollment.account, "alice@example.com");
    assert_eq!(enrollment.issuer, "Example");
    assert_eq!(enrollment.algorithm, Algorithm::Sha1);
    assert_eq!(enrollment.digits, 6);
    assert_eq!(enrollment.period, 30);
    assert!(
        enrollment.secret() == RFC_SECRET,
        "unexpected fixture secret"
    );
    match enrollment.code_at(59.0) {
        Ok((code, remaining)) => {
            assert!(code == "287082", "unexpected RFC TOTP code");
            assert_eq!(remaining, 1);
        }
        Err(_) => panic!("public RFC enrollment must generate a TOTP code"),
    }
}

fn assert_error(path: &Path, expected: &str) {
    let error = match read_enrollment(path) {
        Ok(_) => panic!("unsafe or ambiguous QR import must fail"),
        Err(error) => error,
    };
    let message = error.to_string();
    assert!(
        !message.contains(RFC_SECRET),
        "error exposed a shared secret"
    );
    assert!(!message.contains("otpauth://"), "error exposed an OTP URI");
    assert!(message == expected, "unexpected sanitized error category");
}

fn assert_png_import(image: &GrayImage) {
    let directory = tempdir().unwrap();
    let path = directory.path().join("enrollment.png");
    image.save_with_format(&path, ImageFormat::Png).unwrap();
    assert_enrollment(&path);
}

fn side_by_side(first: &GrayImage, second: &GrayImage) -> GrayImage {
    let spacing = 48;
    let mut image = GrayImage::from_pixel(
        first.width() + second.width() + spacing,
        first.height().max(second.height()),
        Luma([255]),
    );
    image::imageops::replace(&mut image, first, 0, 0);
    image::imageops::replace(&mut image, second, i64::from(first.width() + spacing), 0);
    image
}

fn exif_orientation(orientation: u16) -> Vec<u8> {
    let mut metadata = b"II".to_vec();
    metadata.extend(42_u16.to_le_bytes());
    metadata.extend(8_u32.to_le_bytes());
    metadata.extend(1_u16.to_le_bytes());
    metadata.extend(0x0112_u16.to_le_bytes());
    metadata.extend(3_u16.to_le_bytes());
    metadata.extend(1_u32.to_le_bytes());
    metadata.extend(orientation.to_le_bytes());
    metadata.extend(0_u16.to_le_bytes());
    metadata.extend(0_u32.to_le_bytes());
    metadata
}

fn crc32(bytes: &[u8]) -> u32 {
    let mut checksum = u32::MAX;
    for byte in bytes {
        checksum ^= u32::from(*byte);
        for _ in 0..8 {
            checksum = (checksum >> 1) ^ (0xedb8_8320 * (checksum & 1));
        }
    }
    !checksum
}

fn rewrite_png_header(path: &Path, width: u32, height: u32, depth: u8, color_type: u8) {
    let mut bytes = fs::read(path).unwrap();
    bytes[16..20].copy_from_slice(&width.to_be_bytes());
    bytes[20..24].copy_from_slice(&height.to_be_bytes());
    bytes[24] = depth;
    bytes[25] = color_type;
    let checksum = crc32(&bytes[12..29]);
    bytes[29..33].copy_from_slice(&checksum.to_be_bytes());
    fs::write(path, bytes).unwrap();
}

#[test]
fn imports_png_without_mutating_the_file() {
    let directory = tempdir().unwrap();
    let path = directory.path().join("enrollment.png");
    qr_image(ENROLLMENT_URI).save(&path).unwrap();
    let original = fs::read(&path).unwrap();
    assert_enrollment(&path);
    assert!(fs::read(&path).unwrap() == original, "input image changed");
}

#[test]
fn imports_jpeg() {
    let directory = tempdir().unwrap();
    let path = directory.path().join("enrollment.jpeg");
    let file = File::create(&path).unwrap();
    JpegEncoder::new_with_quality(file, 95)
        .encode_image(&qr_image(ENROLLMENT_URI))
        .unwrap();
    assert_enrollment(&path);
}

#[test]
fn imports_unicode_filename() {
    let directory = tempdir().unwrap();
    let path = directory.path().join("验证器 🔐.png");
    qr_image(ENROLLMENT_URI).save(&path).unwrap();
    assert_enrollment(&path);
}

#[test]
fn sniffs_png_even_with_a_jpeg_extension() {
    let directory = tempdir().unwrap();
    let path = directory.path().join("enrollment.jpg");
    qr_image(ENROLLMENT_URI)
        .save_with_format(&path, ImageFormat::Png)
        .unwrap();
    assert_enrollment(&path);
}

#[test]
fn imports_rotated_90_degrees() {
    assert_png_import(&image::imageops::rotate90(&qr_image(ENROLLMENT_URI)));
}

#[test]
fn imports_rotated_180_degrees() {
    assert_png_import(&image::imageops::rotate180(&qr_image(ENROLLMENT_URI)));
}

#[test]
fn imports_rotated_270_degrees() {
    assert_png_import(&image::imageops::rotate270(&qr_image(ENROLLMENT_URI)));
}

#[test]
fn imports_all_jpeg_exif_orientations() {
    let directory = tempdir().unwrap();
    let original = DynamicImage::ImageLuma8(qr_image(ENROLLMENT_URI));
    for orientation in 1..=8 {
        let inverse = match orientation {
            6 => 8,
            8 => 6,
            other => other,
        };
        let mut stored = original.clone();
        stored.apply_orientation(image::metadata::Orientation::from_exif(inverse).unwrap());
        let path = directory
            .path()
            .join(format!("orientation-{orientation}.jpg"));
        let mut encoder = JpegEncoder::new_with_quality(File::create(&path).unwrap(), 95);
        encoder
            .set_exif_metadata(exif_orientation(u16::from(orientation)))
            .unwrap();
        encoder.encode_image(&stored).unwrap();
        assert_enrollment(&path);
    }
}

#[test]
fn imports_inverted_pixels() {
    let mut image = qr_image(ENROLLMENT_URI);
    image::imageops::invert(&mut image);
    assert_png_import(&image);
}

#[test]
fn composites_transparent_background_on_white() {
    let source = qr_image(ENROLLMENT_URI);
    let image = RgbaImage::from_fn(source.width(), source.height(), |column, row| {
        let alpha = if source.get_pixel(column, row)[0] == 0 {
            255
        } else {
            0
        };
        Rgba([0, 0, 0, alpha])
    });
    let directory = tempdir().unwrap();
    let path = directory.path().join("transparent.png");
    image.save(&path).unwrap();
    assert_enrollment(&path);
}

#[test]
fn composites_partially_transparent_colored_pixels() {
    let source = qr_image(ENROLLMENT_URI);
    let image = RgbaImage::from_fn(source.width(), source.height(), |column, row| {
        let alpha = if source.get_pixel(column, row)[0] == 0 {
            192
        } else {
            0
        };
        Rgba([12, 30, 48, alpha])
    });
    let directory = tempdir().unwrap();
    let path = directory.path().join("partial-alpha.png");
    image.save(&path).unwrap();
    assert_enrollment(&path);
}

#[test]
fn rejects_two_distinct_totp_codes() {
    let directory = tempdir().unwrap();
    let path = directory.path().join("ambiguous.png");
    side_by_side(&qr_image(ENROLLMENT_URI), &qr_image(SECOND_URI))
        .save(&path)
        .unwrap();
    assert_error(&path, "Image contains multiple different TOTP QR codes");
}

#[test]
fn accepts_duplicate_identical_totp_codes() {
    let image = qr_image(ENROLLMENT_URI);
    assert_png_import(&side_by_side(&image, &image));
}

#[test]
fn ignores_unrelated_code_alongside_totp() {
    assert_png_import(&side_by_side(
        &qr_image("https://example.com/not-an-enrollment"),
        &qr_image(ENROLLMENT_URI),
    ));
}

#[test]
fn aggregates_distinct_totp_codes_across_normal_and_inverted_passes() {
    let directory = tempdir().unwrap();
    let path = directory.path().join("mixed-polarities.png");
    let mut inverted = qr_image(SECOND_URI);
    image::imageops::invert(&mut inverted);
    side_by_side(&qr_image(ENROLLMENT_URI), &inverted)
        .save(&path)
        .unwrap();
    assert_error(&path, "Image contains multiple different TOTP QR codes");
}

#[test]
fn deduplicates_same_payload_across_normal_and_inverted_passes() {
    let original = qr_image(ENROLLMENT_URI);
    let mut inverted = original.clone();
    image::imageops::invert(&mut inverted);
    assert_png_import(&side_by_side(&original, &inverted));
}

#[test]
fn finds_inverted_totp_alongside_unrelated_normal_code() {
    let mut inverted = qr_image(ENROLLMENT_URI);
    image::imageops::invert(&mut inverted);
    assert_png_import(&side_by_side(&qr_image("unrelated"), &inverted));
}

#[test]
fn rejects_malformed_enrollment_without_echoing_payload() {
    let directory = tempdir().unwrap();
    let path = directory.path().join("malformed.png");
    qr_image(&format!("{ENROLLMENT_URI}&digits=7"))
        .save(&path)
        .unwrap();
    assert_error(&path, "No valid TOTP QR code found");
}

#[test]
fn rejects_unrelated_qr_payload() {
    let directory = tempdir().unwrap();
    let path = directory.path().join("unrelated.png");
    qr_image("https://example.com/unrelated")
        .save(&path)
        .unwrap();
    assert_error(&path, "No valid TOTP QR code found");
}

#[test]
fn rejects_image_without_qr_code() {
    let directory = tempdir().unwrap();
    let path = directory.path().join("blank.png");
    GrayImage::from_pixel(128, 128, Luma([255]))
        .save(&path)
        .unwrap();
    assert_error(&path, "No valid TOTP QR code found");
}

#[test]
fn rejects_invalid_image_without_library_details() {
    let directory = tempdir().unwrap();
    let path = directory.path().join("invalid.png");
    let mut bytes = b"\x89PNG\r\n\x1a\n".to_vec();
    bytes.extend_from_slice(ENROLLMENT_URI.as_bytes());
    fs::write(&path, bytes).unwrap();
    assert_error(&path, "Unable to decode image");
}

#[test]
fn rejects_non_image_bytes() {
    let directory = tempdir().unwrap();
    let path = directory.path().join("not-an-image.png");
    fs::write(&path, ENROLLMENT_URI).unwrap();
    assert_error(&path, "Only PNG and JPEG images are supported");
}

#[test]
fn rejects_missing_file() {
    let directory = tempdir().unwrap();
    assert_error(
        &directory.path().join("missing.png"),
        "Unable to read a local image file",
    );
}

#[test]
fn rejects_directory() {
    let directory = tempdir().unwrap();
    assert_error(directory.path(), "Image path must be a regular file");
}

#[cfg(unix)]
#[test]
fn rejects_non_regular_socket_without_opening_it() {
    let directory = tempfile::Builder::new()
        .prefix("qr-")
        .tempdir_in("/tmp")
        .unwrap();
    let path = directory.path().join("socket.png");
    let _listener = std::os::unix::net::UnixListener::bind(&path).unwrap();
    assert_error(&path, "Image path must be a regular file");
}

#[test]
fn rejects_unsupported_actual_format_despite_png_extension() {
    let directory = tempdir().unwrap();
    let path = directory.path().join("actually-gif.png");
    fs::write(
        &path,
        b"GIF89a\x01\x00\x01\x00\x80\x00\x00\x00\x00\x00\xff\xff\xff\x2c\x00\x00\x00\x00\x01\x00\x01\x00\x00\x02\x02\x44\x01\x00\x3b",
    )
    .unwrap();
    assert_error(&path, "Only PNG and JPEG images are supported");
}

#[test]
fn rejects_file_one_byte_over_twenty_mib() {
    let directory = tempdir().unwrap();
    let path = directory.path().join("too-large.png");
    File::create(&path)
        .unwrap()
        .set_len(MAX_FILE_BYTES + 1)
        .unwrap();
    assert_error(&path, "Image file exceeds the 20 MiB limit");
}

#[test]
fn accepts_file_at_exact_twenty_mib_limit() {
    let directory = tempdir().unwrap();
    let path = directory.path().join("at-limit.png");
    qr_image(ENROLLMENT_URI).save(&path).unwrap();
    File::options()
        .write(true)
        .open(&path)
        .unwrap()
        .set_len(MAX_FILE_BYTES)
        .unwrap();
    assert_enrollment(&path);
}

#[test]
fn rejects_declared_pixel_count_before_decoding_image_data() {
    let directory = tempdir().unwrap();
    let path = directory.path().join("oversized-dimensions.png");
    qr_image(ENROLLMENT_URI).save(&path).unwrap();
    rewrite_png_header(&path, 8_000, 5_001, 8, 0);
    assert_error(&path, "Image exceeds the 40,000,000 pixel limit");
}

#[test]
fn rejects_declared_jpeg_pixel_count_before_decoding_image_data() {
    let directory = tempdir().unwrap();
    let path = directory.path().join("oversized-dimensions.jpg");
    qr_image(ENROLLMENT_URI).save(&path).unwrap();
    let mut bytes = fs::read(&path).unwrap();
    let frame = bytes
        .windows(2)
        .position(|marker| marker == [0xff, 0xc0])
        .unwrap();
    bytes[frame + 5..frame + 7].copy_from_slice(&5_001_u16.to_be_bytes());
    bytes[frame + 7..frame + 9].copy_from_slice(&8_000_u16.to_be_bytes());
    fs::write(&path, bytes).unwrap();
    assert_error(&path, "Image exceeds the 40,000,000 pixel limit");
}

#[test]
fn rejects_excessive_decoded_allocation_within_pixel_limit() {
    let directory = tempdir().unwrap();
    let path = directory.path().join("oversized-allocation.png");
    qr_image(ENROLLMENT_URI).save(&path).unwrap();
    rewrite_png_header(&path, 8_000, 5_000, 16, 6);
    assert_error(&path, "Image exceeds the decoding memory limit");
}

#[test]
fn rejects_extreme_header_dimensions_without_overflow() {
    let directory = tempdir().unwrap();
    let path = directory.path().join("extreme-dimensions.png");
    qr_image(ENROLLMENT_URI).save(&path).unwrap();
    rewrite_png_header(&path, u32::MAX, u32::MAX, 8, 0);
    assert_error(&path, "Unable to decode image");
}

fn assert_rejects_valid_and_malformed_candidates(inverted: bool) {
    let directory = tempdir().unwrap();
    let path = directory.path().join("valid-and-malformed.png");
    let mut malformed = qr_image(&format!("{ENROLLMENT_URI}&digits=7"));
    if inverted {
        image::imageops::invert(&mut malformed);
    }
    side_by_side(&qr_image(ENROLLMENT_URI), &malformed)
        .save(&path)
        .unwrap();
    assert_error(&path, "Image contains multiple different TOTP QR codes");
}

#[test]
fn rejects_valid_and_malformed_totp_candidates_with_normal_pixels() {
    assert_rejects_valid_and_malformed_candidates(false);
}

#[test]
fn rejects_valid_and_malformed_totp_candidates_with_inverted_pixels() {
    assert_rejects_valid_and_malformed_candidates(true);
}

#[test]
fn imports_large_allowed_png_without_detection_overflow() {
    let directory = tempdir().unwrap();
    let path = directory.path().join("large-enrollment.png");
    let image = QrCode::new(ENROLLMENT_URI.as_bytes())
        .expect("public fixture must fit in a QR code")
        .render::<Luma<u8>>()
        .module_dimensions(120, 120)
        .build();
    assert_eq!(image.dimensions(), (5_880, 5_880));
    image.save(&path).unwrap();
    assert!(fs::metadata(&path).unwrap().len() <= MAX_FILE_BYTES);
    assert_enrollment(&path);
}
