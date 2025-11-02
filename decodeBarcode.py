import cv2
from pyzbar import pyzbar

def decode_barcode(image_path):
    """
    Decodes a barcode from the given image file and returns the data.
    
    Requirements:
    - Install dependencies: pip install opencv-python pyzbar
    
    Args:
    image_path (str): Path to the image file containing the barcode.
    
    Returns:
    str: The decoded barcode data, or None if not found.
    """
    # Load the image
    image = cv2.imread(image_path)
    
    if image is None:
        print(f"Error: Could not load image from {image_path}")
        return None
    
    # Decode barcodes (pyzbar handles 1D barcodes like UPC/EAN)
    decoded_objects = pyzbar.decode(image)
    
    if not decoded_objects:
        print("No barcode found in the image.")
        return None
    
    # Extract and print the data from the first barcode (assuming one)
    for obj in decoded_objects:
        data = obj.data.decode('utf-8')
        barcode_type = obj.type
        print(f"Decoded {barcode_type} barcode: {data}")
        return data
    
    return None

# Example usage
if __name__ == "__main__":
    # Replace 'your_image.jpg' with the path to your uploaded image
    image_path = 'your_image.jpg'  # e.g., the path where you saved the uploaded image
    result = decode_barcode(image_path)
    if result:
        print(f"Final result: {result}")
