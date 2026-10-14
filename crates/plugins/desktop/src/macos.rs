//! Exact-version `ScreenCaptureKit` adapter; selected-app filters cannot expose other apps [D204,D208 A4].
use crate::{
    capture::{Capture, CapturedFrame, Rect},
    protocol::{Size, Target},
};
use screencapturekit::{
    cm::{CMSampleBuffer, CMSampleBufferSCExt, SCFrameStatus},
    prelude::*,
};
use std::{
    io,
    sync::{Arc, Mutex},
};

fn unavailable(_: impl std::fmt::Display) -> io::Error {
    io::Error::other("Desktop capture is unavailable.")
}

pub struct Surface {
    capture_ticks: u64,
}
impl CapturedFrame for Surface {
    fn capture_ticks(&self) -> u64 {
        self.capture_ticks
    }
}

pub struct MacCapture {
    stream: SCStream,
    running: bool,
    latest: Arc<Mutex<Option<Surface>>>,
    display_origin: (f64, f64),
    filter: SCContentFilter,
    config: SCStreamConfiguration,
    size: Size,
    rect: Rect,
    window: bool,
}

fn config(size: Size, rect: Rect, origin: (f64, f64)) -> io::Result<SCStreamConfiguration> {
    size.validate()?;
    if !rect.valid() {
        return Err(io::Error::other("Invalid desktop geometry."));
    }
    let ratio = (f64::from(size.width) / rect.width).min(f64::from(size.height) / rect.height);
    let w = rect.width * ratio;
    let h = rect.height * ratio;
    SCStreamConfiguration::new()
        .with_width(size.width)
        .with_height(size.height)
        .with_background_color_rgba(0.0, 0.0, 0.0, 0.0)
        .with_pixel_format(PixelFormat::BGRA)
        .with_queue_depth(3)
        .with_fps(120)
        .with_source_rect(CGRect::new(
            rect.x - origin.0,
            rect.y - origin.1,
            rect.width,
            rect.height,
        ))
        .with_destination_rect(CGRect::new(
            (f64::from(size.width) - w) / 2.0,
            (f64::from(size.height) - h) / 2.0,
            w,
            h,
        ))
        .with_scales_to_fit(true)
        .with_preserves_aspect_ratio(true)
        .map_err(unavailable)
}

impl Capture for MacCapture {
    type Frame = Surface;
    fn start(target: &Target, size: Size, rect: Rect) -> io::Result<Self> {
        size.validate()?;
        let content = SCShareableContent::get().map_err(unavailable)?;
        let displays = content.displays();
        let (filter, display) = match *target {
            Target::Window {
                window_id,
                owner_pid,
            } => {
                let window = content
                    .windows()
                    .into_iter()
                    .find(|w| {
                        w.window_id() == window_id
                            && w.owning_application()
                                .is_some_and(|a| a.process_id() == owner_pid)
                    })
                    .ok_or_else(|| unavailable("window"))?;
                let app = window
                    .owning_application()
                    .ok_or_else(|| unavailable("app"))?;
                let display = displays
                    .iter()
                    .find(|d| {
                        let f = d.frame();
                        rect.x < f.origin.x + f.size.width
                            && rect.x + rect.width > f.origin.x
                            && rect.y < f.origin.y + f.size.height
                            && rect.y + rect.height > f.origin.y
                    })
                    .ok_or_else(|| unavailable("display"))?;
                // The app inclusion filter tracks newly opened menus/sheets without enumerating
                // every frame. Cropping confines it to the selected window's point rectangle.
                let filter = SCContentFilter::create()
                    .with_display(display)
                    .with_including_applications(&[&app], &[])
                    .build()
                    .map_err(unavailable)?;
                (filter, display)
            }
            Target::Screen { display_id } => {
                let display = displays
                    .iter()
                    .find(|d| d.display_id() == display_id)
                    .ok_or_else(|| unavailable("display"))?;
                (
                    SCContentFilter::create()
                        .with_display(display)
                        .with_excluding_windows(&[])
                        .build()
                        .map_err(unavailable)?,
                    display,
                )
            }
        };
        let frame = display.frame();
        let display_origin = (frame.origin.x, frame.origin.y);
        let latest = Arc::new(Mutex::new(None));
        let slot = Arc::clone(&latest);
        let configuration = config(size, rect, display_origin)?;
        let mut stream = SCStream::new(&filter, &configuration).map_err(unavailable)?;
        stream
            .add_output_handler(
                move |sample: CMSampleBuffer, _: SCStreamOutputType| {
                    if sample.frame_status() == Some(SCFrameStatus::Complete)
                        && sample.display_time().is_some()
                        && let Ok(mut latest) = slot.lock()
                    {
                        *latest = sample
                            .display_time()
                            .map(|capture_ticks| Surface { capture_ticks });
                    }
                },
                SCStreamOutputType::Screen,
            )
            .map_err(unavailable)?;
        stream.start_capture().map_err(unavailable)?;
        Ok(Self {
            stream,
            running: true,
            latest,
            display_origin,
            filter,
            config: configuration,
            size,
            rect,
            window: matches!(target, Target::Window { .. }),
        })
    }
    fn resize(&mut self, size: Size, rect: Rect) -> io::Result<()> {
        let configuration = config(size, rect, self.display_origin)?;
        self.stream
            .update_configuration(&configuration)
            .map_err(unavailable)?;
        self.config = configuration;
        self.size = size;
        self.rect = rect;
        if let Ok(mut latest) = self.latest.lock() {
            *latest = None;
        }
        Ok(())
    }
    fn copy_pixels(&self) -> io::Result<Vec<u8>> {
        use screencapturekit::screenshot_manager::{CGImageExt, SCScreenshotManager};
        // Stream buffers are framework-owned and their byte views require unsafe Rust.
        // The pinned wrapper supplies an owned image copy instead; #146 measures its cost.
        let mut pixels = SCScreenshotManager::capture_image(&self.filter, &self.config)
            .map_err(unavailable)?
            .bgra_data()
            .map_err(unavailable)?;
        if self.window {
            fill_bands(&mut pixels, self.size, self.rect)?;
        }
        Ok(pixels)
    }
    fn take_latest(&self) -> Option<Surface> {
        self.latest.lock().ok()?.take()
    }
    fn stop(&mut self) -> io::Result<()> {
        if !self.running {
            return Ok(());
        }
        self.running = false;
        self.stream.stop_capture().map_err(unavailable)
    }
}
impl Drop for MacCapture {
    fn drop(&mut self) {
        let _ = self.stop();
    }
}

// Native APIs expose pixels, not another application's NSWindow background property.
// Infer a flat background from the modal opaque color in a bounded 32x32 grid.
// Composite transparent app-filtered gaps onto it before H.264 discards alpha;
// neither a desktop image nor another application's pixels enter this estimate.
#[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
fn fill_bands(pixels: &mut [u8], size: Size, rect: Rect) -> io::Result<()> {
    let width = size.width as usize;
    let height = size.height as usize;
    if pixels.len() != width * height * 4 {
        return Err(unavailable("pixels"));
    }
    let ratio = (f64::from(size.width) / rect.width).min(f64::from(size.height) / rect.height);
    let left = ((f64::from(size.width) - rect.width * ratio) / 2.0).floor() as usize;
    let top = ((f64::from(size.height) - rect.height * ratio) / 2.0).floor() as usize;
    let right = width - left;
    let bottom = height - top;
    let mut histogram = std::collections::BTreeMap::<[u8; 3], usize>::new();
    for row in 0..32 {
        for col in 0..32 {
            let x = left + (right - left - 1) * col / 31;
            let y = top + (bottom - top - 1) * row / 31;
            let pixel = &pixels[(y * width + x) * 4..(y * width + x + 1) * 4];
            if pixel[3] == 255 {
                *histogram.entry([pixel[0], pixel[1], pixel[2]]).or_default() += 1;
            }
        }
    }
    let color = histogram
        .into_iter()
        .max_by_key(|(_, count)| *count)
        .map_or([0; 3], |(color, _)| color);
    for y in 0..height {
        for x in 0..width {
            let pixel = &mut pixels[(y * width + x) * 4..(y * width + x + 1) * 4];
            if x < left || x >= right || y < top || y >= bottom {
                pixel[..3].copy_from_slice(&color);
            } else if pixel[3] != 255 {
                let inverse = 255 - u16::from(pixel[3]);
                for c in 0..3 {
                    pixel[c] =
                        (u16::from(pixel[c]) + u16::from(color[c]) * inverse / 255).min(255) as u8;
                }
            }
            pixel[3] = 255;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn very_thin_valid_outputs_keep_a_nonempty_sampling_region() {
        for (width, height) in [(2, 4096), (4096, 2)] {
            let size = Size {
                width,
                height,
                canvas_width: f64::from(width),
                canvas_height: f64::from(height),
                backing_scale: 1.0,
            };
            size.validate().unwrap();
            let mut pixels = vec![255; width as usize * height as usize * 4];
            fill_bands(
                &mut pixels,
                size,
                Rect {
                    x: 0.0,
                    y: 0.0,
                    width: 500.0,
                    height: 300.0,
                },
            )
            .unwrap();
            assert!(pixels.as_chunks::<4>().0.iter().all(|p| p[3] == 255));
        }
    }
}
