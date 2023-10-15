import string
import random
import sys

if sys.version_info[0] < 3:
    import Tkinter as tk
    import tkMessageBox as messagebox
else:
    import tkinter as tk
    from tkinter import messagebox


def generate_strong_password(length=12):
    # Check repeat characters (case insensitive)
    def has_repeating_characters(input_string):
        seen_characters = set()
        for char in input_string:
            if char.lower() in seen_characters:
                return True
            seen_characters.add(char.lower())
        return False

    # Check consecutive characters
    def has_consecutive_characters(input_string, char_set):
        for i in range(len(input_string) - 1):
            if input_string[i] in char_set and input_string[i + 1] in char_set:
                return True
        return False

    # Check sequential characters (3+)
    def has_sequential_characters(input_string):
        for i in range(len(input_string) - 2):
            if (ord(input_string[i]) + 1 == ord(input_string[i + 1])) and (
                ord(input_string[i + 1]) + 1 == ord(input_string[i + 2])
            ):
                return True
        return False

    def contains_at_least_two_characters(input_string, char_set):
        count = 0
        for i in input_string:
            if i in char_set:
                count += 1
            if count == 2:
                return True
        return False

    uppercase_letters = string.ascii_uppercase
    lowercase_letters = string.ascii_lowercase
    digits = string.digits
    special_characters = "!@#$%^&*()_+[]{}|;:,.<>?"

    all_characters = uppercase_letters + lowercase_letters + digits + special_characters

    while True:
        # Generate a random password
        password = "".join([random.choice(all_characters) for _ in range(length)])

        if (
            not has_repeating_characters(password)
            and not has_consecutive_characters(password, uppercase_letters)
            and not has_consecutive_characters(password, lowercase_letters)
            and not has_consecutive_characters(password, digits)
            and not has_sequential_characters(password)
            and not password.isalpha()
            and not password.isdigit()
            and contains_at_least_two_characters(password, uppercase_letters)
            and contains_at_least_two_characters(password, lowercase_letters)
            and contains_at_least_two_characters(password, digits)
            and contains_at_least_two_characters(password, special_characters)
        ):
            return password


# Function to generate a random password
def generate_password(event=None):
    password_length = int(length_entry.get())

    if not validate_password_length(password_length):
        return

    password = generate_strong_password(password_length)
    generated_password.config(state="normal")
    generated_password.delete(1.0, tk.END)  # Clear the text box
    generated_password.insert(tk.END, password, "center")  # Set the generated password
    generated_password.config(state="disabled")
    copy_button.config(state="normal")  # Enable the "Copy to Clipboard" button


# Function to copy the generated password to the clipboard using tkinter
def copy_to_clipboard():
    password = generated_password.get(1.0, tk.END)
    if password:
        root.clipboard_clear()
        root.clipboard_append(password)
        root.update()


# Validate that the input in the length_entry field is a number
def validate_input(P):
    return P == "" or P.isdigit()


def validate_password_length(length):
    return 12 <= length <= 25


# Function to update the state of the generate button
def update_generate_button_state(event=None):
    password_length = length_entry.get()
    if password_length.isdigit() and validate_password_length(int(password_length)):
        generate_button.config(state="normal")
    else:
        generate_button.config(state="disabled")


if __name__ == "__main__":
    # Create the main window
    root = tk.Tk()
    root.title("PyPassGen")

    # Create and pack GUI elements
    length_label = tk.Label(root, text="Password Length:")
    length_label.grid(row=0, column=0)
    validate_input_func = root.register(validate_input)
    length_entry = tk.Entry(
        root, validate="key", validatecommand=(validate_input_func, "%P")
    )
    length_entry.grid(row=0, column=1)

    # Create a text box to display the generated password (read-only)
    generated_password = tk.Text(root, height=1, width=30, state="disabled")
    generated_password.tag_configure("center", justify="center")
    generated_password.grid(row=1, column=0, columnspan=2)

    # Create the "Generate Password" and "Copy to Clipboard" buttons
    generate_button = tk.Button(
        root, text="Generate Password", command=generate_password, state="disabled"
    )
    generate_button.grid(row=2, column=0)

    copy_button = tk.Button(
        root, text="Copy to Clipboard", command=copy_to_clipboard, state="disabled"
    )
    copy_button.grid(row=2, column=1)

    # Bind the "Enter" key to the password generation function
    root.bind("<Return>", generate_password)

    # Bind the length entry field to update the generate button state
    length_entry.bind("<KeyRelease>", update_generate_button_state)

    # Start the main loop
    root.mainloop()
