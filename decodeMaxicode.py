import cv2
from pyzbar import pyzbar

def decode_maxicode(image_path):
    """
    Decodes a MaxiCode from the given image file and returns the data.
    
    Requirements:
    - Install dependencies: pip install opencv-python pyzbar
    
    Args:
    image_path (str): Path to the image file containing the MaxiCode.
    
    Returns:
    str: The decoded MaxiCode data, or None if not found.
    """
    # Load the image
    image = cv2.imread(image_path)
    
    if image is None:
        print(f"Error: Could not load image from {image_path}")
        return None
    
    # Decode MaxiCodes (pyzbar handles MaxiCode via the same decode function)
    decoded_objects = pyzbar.decode(image)
    
    if not decoded_objects:
        print("No MaxiCode found in the image.")
        return None
    
    # Extract and print the data from the first MaxiCode (assuming one)
    for obj in decoded_objects:
        data = obj.data.decode('utf-8')
        code_type = obj.type
        print(f"Decoded {code_type} MaxiCode: {data}")
        return data
    
    return None

# Example usage
if __name__ == "__main__":
    # Replace 'maxicode_image.jpg' with the path to your uploaded MaxiCode image
    image_path = 'maxicode_image.jpg'  # e.g., the path where you saved the uploaded image
    result = decode_maxicode(image_path)
    if result:
        print(f"Final result: {result}")
