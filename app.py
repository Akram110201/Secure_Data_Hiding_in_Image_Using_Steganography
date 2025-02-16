from flask import Flask, render_template, request, redirect, url_for, send_file, flash
from PIL import Image, UnidentifiedImageError
import io
import logging
logging.basicConfig(level=logging.DEBUG)


app = Flask(__name__)
app.secret_key = 'your_secret_key'  # Required for flashing messages

# Caesar Cipher Encryption
def encrypt_text(text, shift=3):
    encrypted_text = ""
    for char in text:
        if char.isalpha():
            shift_amount = shift % 26
            if char.islower():
                encrypted_text += chr(((ord(char) - ord('a') + shift_amount) % 26) + ord('a'))
            else:
                encrypted_text += chr(((ord(char) - ord('A') + shift_amount) % 26) + ord('A'))
        else:
            encrypted_text += char
    return encrypted_text

# Caesar Cipher Decryption
def decrypt_text(text, shift=3):
    return encrypt_text(text, -shift)  # Reverse the shift for decryption

# LSB Steganography to hide text in image
def hide_text_in_image(image, text):
    binary_text = ''.join(format(ord(char), '08b') for char in text)
    binary_text += '1111111111111110'  # Delimiter to mark end of text

    pixels = list(image.getdata())
    if len(binary_text) > len(pixels) * 3:
        raise ValueError("Text too large to hide in image")

    index = 0
    for i in range(len(pixels)):
        pixel = list(pixels[i])
        for j in range(3):  # RGB channels
            if index < len(binary_text):
                pixel[j] = pixel[j] & ~1 | int(binary_text[index])
                index += 1
        pixels[i] = tuple(pixel)

    new_image = Image.new(image.mode, image.size)
    new_image.putdata(pixels)
    return new_image

# LSB Steganography to extract text from image
def extract_text_from_image(image):
    pixels = list(image.getdata())
    binary_text = ''
    for pixel in pixels:
        for value in pixel[:3]:  # RGB channels
            binary_text += str(value & 1)
        if '1111111111111110' in binary_text:  # Check for delimiter
            binary_text = binary_text[:binary_text.index('1111111111111110')]
            text = ''.join(chr(int(binary_text[i:i+8], 2)) for i in range(0, len(binary_text), 8))
            return text
    return "No hidden text found"


# Validate image file
def validate_image(file):
    try:
        # Attempt to open the image file
        image = Image.open(file)
        image.verify()  # Verify that the file is a valid image
        file.seek(0)  # Reset file pointer to the beginning
        return True
    except (UnidentifiedImageError, IOError):
        return False

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/encrypt', methods=['POST'])
def encrypt():
    if 'image' not in request.files or 'message' not in request.form:
        flash("Please upload an image and enter a message.")
        return redirect(url_for('index'))

    image_file = request.files['image']
    message = request.form['message']
    
    # Handle empty shift value
    shift_input = request.form.get('shift', '').strip()
    shift = int(shift_input) if shift_input.isdigit() else 3  # Default to 3 if empty or invalid

    try:
        # Validate the image file
        if not validate_image(image_file):
            flash("Unsupported image format. Please upload a valid JPEG or PNG file.")
            return redirect(url_for('index'))
        
        # Open the image
        image = Image.open(image_file)
        if image.mode != 'RGB':
            image = image.convert('RGB')

        # Encrypt the message
        encrypted_message = encrypt_text(message, shift)

        # Hide the encrypted message in the image
        stego_image = hide_text_in_image(image, encrypted_message)

        # Save the stego image to a byte stream
        byte_stream = io.BytesIO()
        stego_image.save(byte_stream, format='PNG')
        byte_stream.seek(0)

        return send_file(byte_stream, mimetype='image/png', as_attachment=True, download_name='stego_image.png')
    except Exception as e:
        flash(str(e))
        return redirect(url_for('index'))

@app.route('/decrypt', methods=['POST'])
def decrypt():
    if 'image' not in request.files:
        flash("Please upload an image.")
        return redirect(url_for('index'))

    image_file = request.files['image']
    
    # Handle empty shift value
    shift_input = request.form.get('shift', '').strip()
    shift = int(shift_input) if shift_input.isdigit() else 3

    try:
        # Validate the image file
        if not validate_image(image_file):
            flash("Unsupported image format. Please upload a valid JPEG or PNG file.")
            return redirect(url_for('index'))
        
        # Open the image
        image = Image.open(image_file)
        if image.mode != 'RGB':
            image = image.convert('RGB')

        # Extract the encrypted message from the image
        encrypted_message = extract_text_from_image(image)
        app.logger.debug(f"Encrypted Message: {encrypted_message}")
        # print(f"Encrypted Message: {encrypted_message}")  # Debug: Print encrypted message

        # Decrypt the message
        decrypted_message = decrypt_text(encrypted_message, shift)
        # print(f"Decrypted Message: {decrypted_message}")  # Debug: Print decrypted message
        app.logger.debug(f"Decrypted Message: {decrypted_message}")

        return render_template('index.html', decrypted_message=decrypted_message)
    except Exception as e:
        flash(str(e))
        return redirect(url_for('index'))

if __name__ == '__main__':
    app.run(debug=True)