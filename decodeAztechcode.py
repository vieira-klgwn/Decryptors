import cv2
from pyzbar import pyzbar

def decode_qr_code(image_path):
    """
    Decodes a QR code from the given image file and returns the data.
    
    Requirements:
    - Install dependencies: pip install opencv-python pyzbar
    
    Args:
    image_path (str): Path to the image file containing the QR code.
    
    Returns:
    str: The decoded QR code data, or None if not found.
    """
    # Load the image
    image = cv2.imread(image_path)
    
    if image is None:
        print(f"Error: Could not load image from {image_path}")
        return None
    
    # Decode QR codes (pyzbar handles QR codes via the same decode function)
    decoded_objects = pyzbar.decode(image)
    
    if not decoded_objects:
        print("No QR code found in the image.")
        return None
    
    # Extract and print the data from the first QR code (assuming one)
    for obj in decoded_objects:
        data = obj.data.decode('utf-8')
        qr_type = obj.type
        print(f"Decoded {qr_type} QR code: {data}")
        return data
    
    return None

# Example usage
if __name__ == "__main__":
    # Replace 'azatech_qr.jpg' with the path to your uploaded AzaTech QR image
    image_path = 'azatech_qr.jpg'  # e.g., the path where you saved the uploaded image
    result = decode_qr_code(image_path)
    if result:
        print(f"Final result: {result}")
