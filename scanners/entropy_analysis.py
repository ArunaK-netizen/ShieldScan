import math

def calculate_entropy(file_path):
    """Calculate Shannon entropy of the file to detect randomness."""
    try:
        with open(file_path, 'rb') as file:
            data = file.read()

        if not data:
            return "safe"

        byte_count = [0] * 256
        for byte in data:
            byte_count[byte] += 1

        entropy = 0
        for count in byte_count:
            if count == 0:
                continue
            probability = count / len(data)
            entropy -= probability * math.log2(probability)

        print(f"Entropy: {entropy}")

        # Threshold for entropy: typically, 7.5+ indicates high randomness (potentially malicious)
        return "unsafe" if entropy > 7.5 else "safe"

    except Exception as e:
        return f"Error calculating entropy: {str(e)}"
