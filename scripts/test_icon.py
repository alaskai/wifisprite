#!/usr/bin/env python3
"""
Test script to verify the icon loads correctly
"""

import tkinter as tk
from PIL import Image, ImageTk
import os

def test_icon():
    """Test loading and displaying the WiFi Sprite icon"""
    root = tk.Tk()
    root.title("WiFi Sprite Icon Test")
    root.geometry("300x200")
    
    try:
        # Test icon path
        icon_path = os.path.join(os.path.dirname(__file__), 'assets', 'image.png')
        print(f"Looking for icon at: {icon_path}")
        
        if os.path.exists(icon_path):
            print("✅ Icon file found!")
            
            # Load icon for window
            icon_image = Image.open(icon_path)
            icon_image_small = icon_image.resize((32, 32), Image.Resampling.LANCZOS)
            icon_photo = ImageTk.PhotoImage(icon_image_small)
            root.iconphoto(True, icon_photo)
            
            # Load larger version for display
            logo_image = icon_image.resize((64, 64), Image.Resampling.LANCZOS)
            logo_photo = ImageTk.PhotoImage(logo_image)
            
            # Display in window
            label = tk.Label(root, image=logo_photo, text="WiFi Sprite Logo Test", 
                           compound=tk.TOP, font=('Arial', 12, 'bold'))
            label.pack(expand=True)
            
            # Keep references
            root.icon_photo = icon_photo
            root.logo_photo = logo_photo
            
            print("✅ Icon loaded successfully!")
            
        else:
            print("❌ Icon file not found!")
            label = tk.Label(root, text="Icon file not found", 
                           font=('Arial', 12), fg='red')
            label.pack(expand=True)
            
    except Exception as e:
        print(f"❌ Error loading icon: {e}")
        label = tk.Label(root, text=f"Error: {e}", 
                       font=('Arial', 10), fg='red', wraplength=250)
        label.pack(expand=True)
    
    root.mainloop()

if __name__ == "__main__":
    test_icon()