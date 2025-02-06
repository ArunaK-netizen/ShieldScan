import customtkinter as ctk

# Initialize the customTkinter window
ctk.set_appearance_mode("dark")  # Options: "dark" (default), "light", "system"
ctk.set_default_color_theme("blue")  # Options: "blue" (default), "green", "dark-blue"

class App(ctk.CTk):
    def __init__(self):
        super().__init__()

        self.title("CustomTkinter Demo")
        self.geometry("400x300")

        # Create a label
        self.label = ctk.CTkLabel(self, text="Welcome to CustomTkinter!", font=("Arial", 18))
        self.label.pack(pady=20)

        # Create a button
        self.button = ctk.CTkButton(self, text="Click Me!", command=self.on_button_click)
        self.button.pack(pady=10)

        # Create a slider
        self.slider = ctk.CTkSlider(self, from_=0, to=100, command=self.on_slider_change)
        self.slider.set(50)
        self.slider.pack(pady=10)

        # Create a switch
        self.switch = ctk.CTkSwitch(self, text="Toggle Mode", command=self.toggle_mode)
        self.switch.pack(pady=20)

    def on_button_click(self):
        self.label.configure(text="Button Clicked!")

    def on_slider_change(self, value):
        self.label.configure(text=f"Slider Value: {int(value)}")

    def toggle_mode(self):
        current_mode = ctk.get_appearance_mode()
        new_mode = "light" if current_mode == "dark" else "dark"
        ctk.set_appearance_mode(new_mode)

if __name__ == "__main__":
    app = App()
    app.mainloop()
