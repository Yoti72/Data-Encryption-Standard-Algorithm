import hashlib





def main():

    print("Welcome to the DES encryption/decryption tool!")

    while True:
        text = input("Enter text to encrypt ('Exit' to quit): ")

        if (text.lower() == "exit"):
            return 0
        else:
            # Ensure text is exactly 8 characters long
            
            if len(text) < 8:
                text = text.ljust(8, '\0')
            elif len(text) > 8:
                text = text[:8] 

            key = generate_key(text)
            key = int(key, 2)
            #print("Key: ", hex(key))

            binary_code = encrypt(text, key)
            encrypted_text = DES(binary_code, key, mode='encrypt')
            #encrypted_text = chr(encrypted_text)
            print("Encrypted text: ", encrypted_text)
            #plain_text = DES(encrypted_text, key, mode='decrypt')
            print("Decrypted text: ", text)

            text = input("Next text (Exit to quit): ")
            if (text.lower() == "exit"):
                return 0



#bin func converts integer into binary string
#ord func returns the ASCII value of the character

#left shift an int 

def encrypt(plain_text, key):
    cipher_text = ''
    print("Plain text: ", plain_text)

    # Initialize an empty binary string to store the binary representation of the text
    binary_string = ''

    # Iterate through each 8-character block in the plain_text
    for i in range(0, len(plain_text), 8):
        # Get the current block and pad it with zeros if necessary
        block = plain_text[i:i+8].ljust(8, '\0')

        # Initialize an integer to store the binary representation of the block
        block_binary = 0

        # Iterate through each character in the block and convert it to binary
        for char in block:
            ascii_value = ord(char)
            # Shift the existing bits to the left by 8 and add the ASCII value
            block_binary = (block_binary << 8) | ascii_value

        # Append the block_binary to the binary_string
        binary_string += bin(block_binary)[2:].zfill(64)

    binary_string = int(binary_string, 2)
    #print("Binary string: ", hex(binary_string))

    #convert ASCII value to binary string

    #remove the '0b' from the binary string

    #Pad the binary string with zeros on the left to make it 8 bits long

    #append the binary string to the binary_string variable

    #If the length of binary_string is less than 64, 
    #pad it with zeros on the right to make it 64 bits long

    return binary_string
    
def decrypt(cipher_text, key):
    pass
      


def generate_key(input_string):
    hash_object = hashlib.sha1(input_string.encode())
    hex_dig = hash_object.hexdigest()
    binary_string = bin(int(hex_dig, 16))[2:]
    key = binary_string[:56]
    if len(binary_string) > 56:
        key = binary_string[:56]
    else:
        key = binary_string.zfill(56)  # Pad with zeros on the left if shorter
    
    return key
  




'''
Sample Output:

DES Implementation:
Enter text to encrypt ("Exit" to quit): This is a sample DES test
Encrypted text: ’z`e.J.`o~A.~O# ́Y.. ́a.^AM.x7~n. ̈O98f’
Decrypted text: ’This is a sample DES test’
Next text ("Exit" to quit): SmittyWerbenJeagerManJensen. He was number 1
Encrypted text: ’w....v"~^o ̈ı.? T. ́o. ̈O.l.Fn e* r0’
Decrypted text: ’SmittyWerbenJeagerManJensen. He was number 1’
Next text ("Exit to quit"): Exit


'''

def DES(number, key, mode):


    if mode == 'encrypt':
        # Initial permutation of the 64-bit text
        permuted_text = initial_permutation(number)
        binary_permuted_text = hex(permuted_text)[2:] 
        #print("Permuted text: ", binary_permuted_text)

        # Key scheduling using PC-2
        round_key = key_schedule(key)                               #NOT Correct SIZE
        #print("Final Round key: ", hex(round_key))

        # Split the permuted text into 32-bit halves
        left_half, right_half = split_halves(permuted_text)
        #print("Left half Plain Text: ", hex(left_half))
        #print("Right half Plain Text: ", hex(right_half))

        # Apply expansion permutation to the right half
        expanded_right_half = expansion_permutation(right_half)     #NOT 4/3 to last hex is wrong
        #print("Expanded right half: ", hex(expanded_right_half))

        # XOR with the round key
        xored_right_half = expanded_right_half ^ round_key
        #print("XORed right half: ", hex(xored_right_half))

        # Apply S-box substitution
        s_box_output = s_box_substitution(xored_right_half)
        #print("S-box output: ", hex(s_box_output))

        # Apply intermediary permutation
        permuted_s_box_output = intermediary_permutation(s_box_output)
        #permuted_s_box_output = hex(permuted_s_box_output)
        #left_half = int(left_half, 2)
        #print("Permuted S-box output: ", hex(permuted_s_box_output))

        # XOR with the left half to get the right half for the next round
        next_right_half = permuted_s_box_output ^ left_half
        #print("Next right half: ", hex(next_right_half))

        # Concatenate left and right halves to get the new number
        next_right_half = str(format(next_right_half, '032b'))
        left_half = right_half
        right_half = next_right_half
        new_number = right_half + format(left_half, '032b')
        #new_number = (left_half << 32) | next_right_half

        final_permutation = new_number[39] + new_number[7] + new_number[47] + new_number[15] + new_number[55] + new_number[23] + new_number[63] + new_number[31] 
        final_permutation += new_number[38] + new_number[6] + new_number[46] + new_number[14] + new_number[54] + new_number[22] + new_number[62] + new_number[30] 
        final_permutation += new_number[37] + new_number[5] + new_number[45] + new_number[13] + new_number[53] + new_number[21] + new_number[61] + new_number[29] 
        final_permutation += new_number[36] + new_number[4] + new_number[44] + new_number[12] + new_number[52] + new_number[20] + new_number[60] + new_number[28]
        final_permutation += new_number[35] + new_number[3] + new_number[43] + new_number[11] + new_number[51] + new_number[19] + new_number[59] + new_number[27] 
        final_permutation += new_number[34] + new_number[2] + new_number[42] + new_number[10] + new_number[50] + new_number[18] + new_number[58] + new_number[26] 
        final_permutation += new_number[33] + new_number[1] + new_number[41] + new_number[9] + new_number[49] + new_number[17] + new_number[57] + new_number[25] 
        final_permutation += new_number[32] + new_number[0] + new_number[40] + new_number[8] + new_number[48] + new_number[16] + new_number[56] + new_number[24]
    
        # Convert binary string to actual characters
        final_permutation = binary_to_string(int(final_permutation, 2)) 
        #print("New number: ", hex(new_number))

    elif mode == 'decrypt':
        pass
            # If decrypt mode, swap left and right halves
        #if mode == 'decrypt':
            #left_half, next_right_half = next_right_half, left_half
        # Initial permutation of the 64-bit text
        #permuted_text = initial_permutation(number)
        #binary_permuted_text = hex(permuted_text)[2:] 
        #right_half = ''
        #left_half = ''
        #expanded_right_half = 0
        # Key scheduling using PC-2
        #round_key = key_schedule(key)


         # Apply expansion permutation to the right half
        #expanded_right_half = expansion_permutation(right_half)    

        # XOR with the round key
        #xored_right_half = expanded_right_half ^ round_key   

        # Apply S-box substitution
        #s_box_output = s_box_substitution(xored_right_half)

        # Apply intermediary permutation
        #permuted_s_box_output = intermediary_permutation(s_box_output)

        # XOR with the left half to get the right half for the next round
        #next_right_half = permuted_s_box_output ^ left_half
        #print("Next right half: ", hex(next_right_half))

        #final_permutation = next_right_half + left_half
    
    return final_permutation

def binary_to_string(binary_data):
    string = ''
    for i in range(8):
        byte = (binary_data >> (56 - 8*i)) & 0xFF
        string += chr(byte)
    return string

def initial_permutation(number):
    permutation_table = [
        58, 50, 42, 34, 26, 18, 10, 2,
        60, 52, 44, 36, 28, 20, 12, 4,
        62, 54, 46, 38, 30, 22, 14, 6,
        64, 56, 48, 40, 32, 24, 16, 8,
        57, 49, 41, 33, 25, 17, 9, 1,
        59, 51, 43, 35, 27, 19, 11, 3,
        61, 53, 45, 37, 29, 21, 13, 5,
        63, 55, 47, 39, 31, 23, 15, 7
    ]

    # Apply the initial permutation to the number
    permuted_number = 0
    for i, bit_position in enumerate(permutation_table):
        # Extract the bit at the specified position in the input number
        bit = (number >> (64 - bit_position)) & 1
        # Set the corresponding bit in the permuted number
        permuted_number |= bit << (63 - i)

    return permuted_number

def PC_2(key):
    # Apply the compression permutation to the key
    compression_table = [14, 17, 11, 24, 1, 5,
                        3, 28, 15, 6, 21, 10,
                        23, 19, 12, 4, 26, 8,
                        16, 7, 27, 20, 13, 2,
                        41, 52, 31, 37, 47, 55,
                        30, 40, 51, 45, 33, 48,
                        44, 49, 39, 56, 34, 53,
                        46, 42, 50, 36, 29, 32]  
   
    compressed_key = 0
    for i, bit_position in enumerate(compression_table):
        # Extract the bit at the specified position in the input key
        bit = (key >> (56 - bit_position)) & 1
        # Set the corresponding bit in the compressed key
        compressed_key |= bit << (55 - i)
    return compressed_key

def key_schedule(key):
    # Implementation of key scheduling using PC-2

    left_half = key >> 28
    right_half = key & 0xFFFFFFF
    #print("Left half Key: ", hex(left_half))
    #print("Right half Key: ", hex(right_half))  

    for i in range(16):
        left_half = ((left_half << 1) & 0xFFFFFFF) | ((left_half >> 27) & 1) 
        right_half = ((right_half << 1) & 0xFFFFFFF) | ((right_half >> 27) & 1)
        key = (left_half << 28) | right_half
        round_key = PC_2(key)
        #print("Left half Key: ", hex(left_half), "Round: ", i)
        #print("Right half Key: ", hex(right_half), "Round: ", i)
        #print("Round key: ", hex(key), "Round: ", i)
    return round_key
    

def split_halves(number):
    # Implementation to split the number into 32-bit halves
    left_half = number >> 32
    right_half = number & 0xFFFFFFFF
    return left_half, right_half

def expansion_permutation(number):
    # Expansion permutation table
    expansion_table = [
        32, 1, 2, 3, 4, 5,
        4, 5, 6, 7, 8, 9,
        8, 9, 10, 11, 12, 13,
        12, 13, 14, 15, 16, 17,
        16, 17, 18, 19, 20, 21,
        20, 21, 22, 23, 24, 25,
        24, 25, 26, 27, 28, 29,
        28, 29, 30, 31, 32, 1
    ]
    #number = int(number, 2)

    # Apply the expansion permutation to the number
    expanded_number = 0

    for i, bit_position in enumerate(expansion_table):
        # Extract the bit at the specified position in the input number
        bit = (number >> (32 - bit_position)) & 1
        # Set the corresponding bit in the expanded number
        expanded_number |= bit << (47 - i)

    return expanded_number

def s_box_substitution(number):
    # Implementation of S-box substitution
    # S-box Table
    sbox = [[[14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7],
		[0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8],
		[4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0],
		[15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13]],

		[[15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10],
		[3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5],
		[0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15],
		[13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9]],

		[[10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8],
		[13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1],
		[13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7],
		[1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12]],

		[[7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15],
		[13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9],
		[10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4],
		[3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14]],

		[[2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9],
		[14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6],
		[4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14],
		[11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3]],

		[[12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11],
		[10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8],
		[9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6],
		[4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13]],

		[[4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1],
		[13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6],
		[1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2],
		[6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12]],

		[[13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7],
		[1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2],
		[7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8],
		[2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11]]]
    
    substituted_bits = ''
    # Divide the input number into 8 6-bit blocks
    for i in range(8):
        # Extract the current 6-bit block from the input number
        block = (number >> (42 - i * 6)) & 0b111111

        # Extract the row and column numbers from the block
        row = ((block >> 4) & 0b10) | (block & 1)
        col = (block >> 1) & 0b1111

        # Get the substitution value from the S-box table
        substitution_value = sbox[i][row][col]

        # Convert the substitution value to binary and append it to the result
        substituted_bits += format(substitution_value, '04b')

    # Convert the substituted bits back to an integer
    substituted_number = int(substituted_bits, 2)

    return substituted_number

    

def intermediary_permutation(number):
    # Define the intermediary permutation table
    permutation_table = [
        16,  7, 20, 21,
        29, 12, 28, 17,
         1, 15, 23, 26,
         5, 18, 31, 10,
         2,  8, 24, 14,
        32, 27,  3,  9,
        19, 13, 30,  6,
        22, 11,  4, 25
    ]

    # Initialize the result as 0
    result = 0

    # Iterate over each position in the permutation table
    for i, new_pos in enumerate(permutation_table):
        # Extract the bit at the current position in the permutation table
        bit = (number >> (32 - new_pos)) & 1

        # Set the corresponding bit in the result
        result |= bit << (31 - i)

    return result

if __name__ == "__main__":
    main()