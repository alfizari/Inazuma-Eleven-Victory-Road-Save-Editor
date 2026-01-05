# inazuma
from tkinter import *
from tkinter import filedialog, messagebox
import os, struct
from main import process_file


MODE = None
data = None
IMPORT_MODE = None
import_data = None
file_path = None



def open_file():
    global MODE, data, file_path

    file_path = filedialog.askopenfilename()
    if not file_path:
        return
    
    file_name = os.path.basename(file_path)

    with open(file_path, 'rb') as f:
        data = bytearray(f.read())

    if file_name == 'AUTOSAVE_data.bin':
        MODE = 'PS4'
        data = bytearray(0x800) + data

    elif file_name.endswith('USERDATALIVE'):
        MODE = 'PC'
        data = process_file(file_path, data)

    update_status()


def players_level(new_level):
    global data 

    if new_level > 99:
        new_level = 99

    level_start_offset = 0x373307
    starting_at = level_start_offset + 0x08

    number_of_entries = 0
    offset = starting_at

    while offset + 4 <= len(data):
        if number_of_entries > 100000:
            break

        entry1, entry2 = struct.unpack_from('<HH', data, offset)
        if entry1 == 0 and entry2 == 0:
            break

        number_of_entries += 1
        offset += 2

    offset = starting_at
    for _ in range(number_of_entries):
        current_level = struct.unpack_from('<H', data, offset)[0]
        if current_level != 0:
            struct.pack_into('<H', data, offset, new_level)
        offset += 2

    messagebox.showinfo("Done", f"Level set to {new_level}")


def max_tokens():
    global data

    max_value = 99999

    tokens = [
        0x2FEB2C, 0x2FEB76, 0x2FEC0A, 0x2FEC54, 0x2FECE8,
        0x2FED32, 0x2FEE5A, 0x2FEBC0, 0x2FEE10, 0x2FEC9E,
        0x2FF38E, 0x2FEDC6, 0x2FF5DE, 0x2FF2FA, 0x2FEF82,
        0x2FEFCC, 0x2FEF38, 0x2FED7C, 0x2FF594, 0x2FF54A,
        0x2FF188, 0x2FF1D2, 0x2FF3D8, 0x2FF422, 0x2FF13E,
        0x2FF0AA, 0x2FF46C, 0x2FEA7A, 0x2FF266, 0x2FEB8A,
        0x2FEAE2, 0x35FE80, 0x35FEDF, 0x35FF9D, 0x35FF3E,
        0x35FFFC, 0x35FDC2, 0x35FE21, 0x2FF2B0
    ]

    for offset in tokens:
        struct.pack_into('<I', data, offset, max_value)

    messagebox.showinfo("Done", "All tokens maxed")


def save_file():
    global data

    if MODE is None:
        return
    
    if MODE == 'PC':
        if data[0x500:0x502] == b'\x00\x00':
            data = process_file(file_path, data)
            with open(file_path, 'wb') as f:
                f.write(data)
        else:
            with open(file_path, 'wb') as f:
                f.write(data)

    elif MODE == 'PS4':
        with open(file_path, 'wb') as f:
            f.write(data[0x800:])

    messagebox.showinfo("Saved", "Save file written successfully")


def import_save():
    global IMPORT_MODE, import_data, data

    import_path = filedialog.askopenfilename()
    if not import_path:
        return
    
    with open(import_path, 'rb') as f:
        import_data = bytearray(f.read())

    import_name = os.path.basename(import_path)

    if import_name.endswith('USERDATALIVE'):
        IMPORT_MODE = 'PC'
        import_data=process_file(import_path, import_data)
    elif import_name == 'AUTOSAVE_data.bin':
        IMPORT_MODE = 'PS4'
        import_data = bytearray(0x800) + import_data


def import_done():
    global IMPORT_MODE, import_data, data

    import_save()

    if not import_data:
        messagebox.showerror("Error", "No import data loaded")
        return

    if IMPORT_MODE == 'PS4' and len(import_data) != 0xBBE493:
        messagebox.showerror("Error", "Cannot import this save")
        return

    data = data[:0x800] + import_data[0x800:0xBBE493] + data[0xBBE493:]
    messagebox.showinfo("Done", "Save imported successfully")




def update_status():
    if MODE:
        status_var.set(f"Loaded: {MODE} | {os.path.basename(file_path)}")
    else:
        status_var.set("No save loaded")


def set_level_from_ui():
    if not data:
        return
    try:
        lvl = int(level_entry.get())
        players_level(lvl)
    except ValueError:
        messagebox.showerror("Error", "Invalid level")


root = Tk()
root.title("Inazuma Save Editor")
root.geometry("420x300")
root.resizable(False, False)

frame = Frame(root, padx=10, pady=10)
frame.pack(fill=BOTH, expand=True)

Button(frame, text="Open Save", width=30, command=open_file).pack(pady=5)

Label(frame, text="Player Level").pack()
level_entry = Entry(frame, justify=CENTER)
level_entry.insert(0, "99")
level_entry.pack()

Button(frame, text="Apply Level", width=30, command=set_level_from_ui).pack(pady=5)
Button(frame, text="Max Tokens", width=30, command=max_tokens).pack(pady=5)
Button(frame, text="Import Save", width=30, command=import_done).pack(pady=5)
Button(frame, text="Save File", width=30, command=save_file).pack(pady=10)

status_var = StringVar(value="No save loaded")
Label(root, textvariable=status_var, relief=SUNKEN, anchor=W).pack(fill=X, side=BOTTOM)

root.mainloop()
