# Product Images

Place your product images in this folder with the following names:

## Required Image Files

**Just name them without extensions - the app will find .png, .jpg, .jpeg, .webp, or .gif automatically!**

- `red-t-shirt` (add .png, .jpg, .jpeg, .webp, or .gif)
- `blue-jeans`
- `sneakers`
- `hoodie`
- `socks`
- `baseball-cap`
- `backpack`
- `sunglasses`
- `watch`
- `leather-wallet`
- `running-shoes`
- `winter-jacket`

**Example:** Name your file `red-t-shirt.png` or `red-t-shirt.jpg` - both work!

## Image Guidelines

- **Format:** PNG, JPG, JPEG, WebP, or GIF (all supported!)
- **Extension:** Optional - just name the file, add any extension you want
- **Recommended Size:** 800x600px or similar aspect ratio
- **File Size:** Keep under 500KB for faster loading
- **Quality:** Medium to high quality for web display

## How It Works

The app automatically detects your image format:
1. Checks for `red-t-shirt.png`
2. If not found, checks `red-t-shirt.jpg`
3. Then checks `.jpeg`, `.webp`, `.gif`
4. If nothing found, shows a placeholder

## Fallback

If an image is missing, the app will show `placeholder.svg` instead.

## Adding New Products

When adding new products to the database, follow this naming convention:
- Convert product name to lowercase
- Replace spaces with hyphens
- Don't worry about the extension!
- Example: "Running Shoes" → `running-shoes.png` or `running-shoes.jpg` (both work!)
