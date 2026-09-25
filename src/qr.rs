use std::collections::HashSet;
use std::fs::{self, File};
use std::io::{Cursor, Read};
use std::path::Path;

use image::{DynamicImage, GrayImage, ImageDecoder, ImageFormat, ImageReader, Limits, Pixel, Rgb};

use crate::enrollment::{Enrollment, parse_enrollment};
use crate::error::{AppError, Result};

const MAX_FILE_BYTES: u64 = 20 * 1024 * 1024;
const MAX_PIXELS: u32 = 40_000_000;
const MAX_DECODE_BYTES: u64 = 256 * 1024 * 1024;
const MAX_DETECTION_SIDE: u32 = 1_024;
const _: () = assert!(2 * (MAX_DETECTION_SIDE as i64 - 1).pow(3) <= i32::MAX as i64);

pub fn read_enrollment(path: &Path) -> Result<Enrollment> {
    let bytes = read_image_file(path)?;
    let mut grayscale = normalize_detection_geometry(decode_grayscale(&bytes)?);
    let mut payloads = HashSet::new();
    for inverted in [false, true] {
        if inverted {
            image::imageops::invert(&mut grayscale);
        }
        let mut prepared = rqrr::PreparedImage::prepare(grayscale.clone());
        for grid in prepared.detect_grids() {
            if let Ok((_, payload)) = grid.decode() {
                payloads.insert(payload);
            }
        }
    }

    let mut candidates = payloads
        .iter()
        .filter(|payload| payload.starts_with("otpauth://totp/"));
    let candidate = candidates
        .next()
        .ok_or_else(|| AppError::new("No valid TOTP QR code found"))?;
    if candidates.next().is_some() {
        return Err(AppError::new(
            "Image contains multiple different TOTP QR codes",
        ));
    }
    parse_enrollment(candidate).map_err(|_| AppError::new("No valid TOTP QR code found"))
}

fn normalize_detection_geometry(grayscale: GrayImage) -> GrayImage {
    let longest_side = grayscale.width().max(grayscale.height());
    if longest_side <= MAX_DETECTION_SIDE {
        return grayscale;
    }
    let scaled_dimension = |dimension| {
        (u64::from(dimension) * u64::from(MAX_DETECTION_SIDE) / u64::from(longest_side)).max(1)
            as u32
    };
    image::imageops::resize(
        &grayscale,
        scaled_dimension(grayscale.width()),
        scaled_dimension(grayscale.height()),
        image::imageops::FilterType::Triangle,
    )
}

fn read_image_file(path: &Path) -> Result<Vec<u8>> {
    let metadata =
        fs::metadata(path).map_err(|_| AppError::new("Unable to read a local image file"))?;
    check_file_metadata(&metadata)?;
    let file = File::open(path).map_err(|_| AppError::new("Unable to read a local image file"))?;
    let metadata = file
        .metadata()
        .map_err(|_| AppError::new("Unable to read a local image file"))?;
    check_file_metadata(&metadata)?;

    let mut bytes = Vec::new();
    file.take(MAX_FILE_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| AppError::new("Unable to read a local image file"))?;
    if bytes.len() as u64 > MAX_FILE_BYTES {
        return Err(AppError::new("Image file exceeds the 20 MiB limit"));
    }
    Ok(bytes)
}

fn check_file_metadata(metadata: &fs::Metadata) -> Result<()> {
    if !metadata.is_file() {
        return Err(AppError::new("Image path must be a regular file"));
    }
    if metadata.len() > MAX_FILE_BYTES {
        return Err(AppError::new("Image file exceeds the 20 MiB limit"));
    }
    Ok(())
}

fn check_dimensions(width: u32, height: u32) -> Result<()> {
    if width == 0 || height == 0 {
        return Err(AppError::new("Unable to decode image"));
    }
    let pixels = u64::from(width) * u64::from(height);
    if pixels > u64::from(MAX_PIXELS) {
        return Err(AppError::new("Image exceeds the 40,000,000 pixel limit"));
    }
    Ok(())
}

fn decode_grayscale(bytes: &[u8]) -> Result<GrayImage> {
    let format = image::guess_format(bytes)
        .map_err(|_| AppError::new("Only PNG and JPEG images are supported"))?;
    if !matches!(format, ImageFormat::Png | ImageFormat::Jpeg) {
        return Err(AppError::new("Only PNG and JPEG images are supported"));
    }

    let mut limits = Limits::default();
    limits.max_image_width = Some(MAX_PIXELS);
    limits.max_image_height = Some(MAX_PIXELS);
    limits.max_alloc = Some(MAX_DECODE_BYTES);
    let mut reader = ImageReader::with_format(Cursor::new(bytes), format);
    reader.limits(limits.clone());
    let mut decoder = reader
        .into_decoder()
        .map_err(|_| AppError::new("Unable to decode image"))?;
    let (width, height) = decoder.dimensions();
    check_dimensions(width, height)?;
    limits
        .reserve(decoder.total_bytes())
        .map_err(|_| AppError::new("Image exceeds the decoding memory limit"))?;
    decoder
        .set_limits(limits)
        .map_err(|_| AppError::new("Image exceeds the decoding memory limit"))?;
    let orientation = decoder
        .orientation()
        .map_err(|_| AppError::new("Unable to decode image"))?;
    let mut image =
        DynamicImage::from_decoder(decoder).map_err(|_| AppError::new("Unable to decode image"))?;
    image.apply_orientation(orientation);

    let rgba = image.into_rgba8();
    Ok(GrayImage::from_fn(
        rgba.width(),
        rgba.height(),
        |column, row| {
            let pixel = rgba.get_pixel(column, row);
            let opacity = u32::from(pixel[3]);
            let composite = |channel| {
                ((u32::from(channel) * opacity + 255 * (255 - opacity) + 127) / 255) as u8
            };
            Rgb([
                composite(pixel[0]),
                composite(pixel[1]),
                composite(pixel[2]),
            ])
            .to_luma()
        },
    ))
}
