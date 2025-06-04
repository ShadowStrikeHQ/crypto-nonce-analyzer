#!/usr/bin/env python3

import argparse
import logging
import binascii
from collections import Counter

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def setup_argparse():
    """
    Sets up the argument parser for the crypto_nonce_analyzer tool.

    Returns:
        argparse.ArgumentParser: The argument parser object.
    """
    parser = argparse.ArgumentParser(description="Analyzes cryptographic nonces for patterns, collisions, or predictability.",
                                     epilog="Example usage: python crypto_nonce_analyzer.py --nonces nonce1.txt nonce2.txt")
    parser.add_argument("nonces", nargs='+', help="Files containing nonces (one nonce per line, hex-encoded)")
    parser.add_argument("--min-length", type=int, default=8, help="Minimum nonce length to consider (in bytes). Default is 8.")
    parser.add_argument("--max-length", type=int, default=32, help="Maximum nonce length to consider (in bytes). Default is 32.")
    parser.add_argument("--detect-collisions", action="store_true", help="Detect and report collisions among nonces.")
    parser.add_argument("--detect-incrementing", action="store_true", help="Detect incrementing nonce patterns")
    parser.add_argument("--output-file", type=str, help="Optional file to write the analysis results to.")

    return parser


def is_hex(s):
    """
    Checks if a string is a valid hexadecimal string.

    Args:
        s (str): The string to check.

    Returns:
        bool: True if the string is a valid hexadecimal string, False otherwise.
    """
    try:
        int(s, 16)
        return True
    except ValueError:
        return False


def load_nonces_from_file(filename, min_length, max_length):
    """
    Loads nonces from a file, validating them and ensuring they are within specified length bounds.

    Args:
        filename (str): The name of the file containing the nonces.
        min_length (int): Minimum length of nonce in bytes.
        max_length (int): Maximum length of nonce in bytes.

    Returns:
        list: A list of validated nonces (bytes objects).

    Raises:
        FileNotFoundError: If the specified file does not exist.
        ValueError: If a line in the file is not a valid hexadecimal string, or length bounds are violated.
    """
    nonces = []
    try:
        with open(filename, 'r') as f:
            for line in f:
                nonce_hex = line.strip()
                if not nonce_hex:  # Skip empty lines
                    continue
                if not is_hex(nonce_hex):
                    raise ValueError(f"Invalid hexadecimal nonce: {nonce_hex}")

                try:
                    nonce_bytes = binascii.unhexlify(nonce_hex)  # Convert hex string to bytes
                except binascii.Error as e:
                     raise ValueError(f"Failed to unhexlify nonce {nonce_hex}: {e}")


                nonce_length = len(nonce_bytes)
                if min_length <= nonce_length <= max_length:
                    nonces.append(nonce_bytes)
                else:
                    logging.warning(f"Nonce {nonce_hex} has invalid length ({nonce_length} bytes). Skipping.")

    except FileNotFoundError:
        logging.error(f"File not found: {filename}")
        raise

    except ValueError as e:
        logging.error(f"Error processing file {filename}: {e}")
        raise

    return nonces



def detect_nonce_collisions(nonces):
    """
    Detects collisions among a list of nonces.

    Args:
        nonces (list): A list of nonces (bytes objects).

    Returns:
        dict: A dictionary where keys are colliding nonces (bytes objects) and values are the number of times they occur.
    """
    nonce_counts = Counter(nonces)
    collisions = {nonce: count for nonce, count in nonce_counts.items() if count > 1}
    return collisions


def detect_incrementing_nonces(nonces):
    """
    Detects potential incrementing patterns among nonces.  This is a rudimentary check and might
    produce false positives.

    Args:
        nonces (list): A list of nonces (bytes objects).

    Returns:
        list: A list of tuples containing incrementing nonce pairs.
    """
    incrementing_pairs = []
    for i in range(len(nonces) - 1):
        try:
            nonce1_int = int.from_bytes(nonces[i], 'big')
            nonce2_int = int.from_bytes(nonces[i+1], 'big')

            if nonce2_int == nonce1_int + 1:
                incrementing_pairs.append((binascii.hexlify(nonces[i]).decode(), binascii.hexlify(nonces[i+1]).decode()))
        except OverflowError:
            logging.warning("Nonce too large to analyze for incrementing pattern.")
        except Exception as e:
            logging.error(f"Error during incrementing nonce check: {e}")

    return incrementing_pairs


def main():
    """
    Main function for the crypto_nonce_analyzer tool.
    """
    parser = setup_argparse()
    args = parser.parse_args()

    all_nonces = []
    for filename in args.nonces:
        try:
            nonces = load_nonces_from_file(filename, args.min_length, args.max_length)
            all_nonces.extend(nonces)
        except (FileNotFoundError, ValueError) as e:
            logging.error(f"Error processing file {filename}: {e}")
            return  # Exit if a file fails to process.  Avoids partial analysis.

    if not all_nonces:
        logging.warning("No valid nonces found in the provided files. Exiting.")
        return

    output_lines = [] # Collect output lines before writing to file/stdout

    if args.detect_collisions:
        collisions = detect_nonce_collisions(all_nonces)
        if collisions:
            output_lines.append("Nonce Collisions:")
            for nonce, count in collisions.items():
                output_lines.append(f"  {binascii.hexlify(nonce).decode()}: {count} occurrences")
        else:
            output_lines.append("No nonce collisions detected.")

    if args.detect_incrementing:
        incrementing_pairs = detect_incrementing_nonces(all_nonces)
        if incrementing_pairs:
            output_lines.append("\nPossible Incrementing Nonce Pairs:")
            for nonce1, nonce2 in incrementing_pairs:
                output_lines.append(f"  {nonce1} -> {nonce2}")
        else:
            output_lines.append("\nNo incrementing nonce pairs detected.")

    if not (args.detect_collisions or args.detect_incrementing):
        output_lines.append("No analysis options selected. Use --detect-collisions and/or --detect-incrementing.")


    if args.output_file:
        try:
            with open(args.output_file, 'w') as outfile:
                for line in output_lines:
                    outfile.write(line + '\n')
            logging.info(f"Analysis results written to {args.output_file}")

        except IOError as e:
            logging.error(f"Error writing to file {args.output_file}: {e}")

    else:
        for line in output_lines:
            print(line)




if __name__ == "__main__":
    main()


# Example usage (create dummy files for testing):
#
# echo "00000001" > nonce1.txt
# echo "00000002" >> nonce1.txt
# echo "00000001" >> nonce1.txt
# echo "00000003" > nonce2.txt
# echo "AABBCCDD" >> nonce2.txt
#
# Run the tool:
# python crypto_nonce_analyzer.py nonce1.txt nonce2.txt --detect-collisions --detect-incrementing --output-file results.txt
#
# Check the output file:
# cat results.txt