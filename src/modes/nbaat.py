import tkinter as tk
import time
import re
import sys
from modes import convert, baat
from tkinter import filedialog, messagebox
from openpyxl import Workbook

# Define a class called FileSelectorApp to store all the various functions 
class FileSelectorApp:
    def __init__(self, root):
        self.root = root
        self.root.withdraw() # Hide the NBAAT File Selector main application window
        self.gui_built = False # A flag to check if the main GUI of the NBAAT file selector window has been built. Default value set to False.
        self.project_name = tk.StringVar()
        self.show_project_name_popup()
        self.root.protocol("WM_DELETE_WINDOW", self.handle_close) # handle closing the window via the top-right “X” button, calling the handle_close() function
    
    # Ask user to confirm if quitting the process
    def handle_close(self):
        if messagebox.askokcancel("Quit", "Do you really want to quit?"):
            self.root.destroy()
            sys.exit()

    # Display the Project Name window to allow user to enter the audit project name 
    def show_project_name_popup(self):

        #Specifications of the Project Name Window
        popup = tk.Toplevel(self.root)
        popup.title("Enter Audit Project Name") # Title of the window
        popup.geometry("350x150")             # Default Size of the window when opened
        popup.minsize(350, 150)               # Minimum window size that can be displayed
        popup.grab_set()
        popup.protocol("WM_DELETE_WINDOW", self.handle_close)  # handle closing the window via the top-right “X” button, calling the handle_close() function 

        tk.Label(popup, text="Please enter Audit Project name:").pack(pady=10) # Text display within the window

        entry = tk.Entry(popup, textvariable=self.project_name, width=30) # The entry bar for users to insert their audit project title input
        entry.pack(pady=5) # Adjust the padding of the entry bar to determine the size of the entry bar
        entry.focus()

        # Check if the user entered an Audit Project Name
        def confirm():
            self.name = self.project_name.get().strip() # Obtain the project name from the user submitted input

            # Prompt users that Project name is required if no name is obtained from the input
            if not self.name:
                messagebox.showwarning("No Project Name specified", "Project name is required.")
                return
            
            # Check the Project Name for any invalid characters
            elif re.search(r'[\\/:*?"<>|]', self.name):
                messagebox.showerror("Invalid Project Name", "Please ensure your project name does not contain these invalid characters: \\ / : * ? \" < > |")
                return

            else:
                popup.destroy() # Close the current popup window
                self.root.deiconify()  # Restore the NBAAT File Selector main window that was hidden
                
                # Ensure the NBAAT File Selector Window is built only once upon openign the exe fir the first time. 
                if not self.gui_built:
                    self.gui_built = True # Set the flag to True to indicate that the main GUI of the NBAAT file selector window has been built.
                    self.build_main_gui() # Redirect user to the NBAAT File Selector main window to select the files for report generation
        
        #"OK" button. Clicking "OK" will trigger the confirm() function
        tk.Button(popup, text="OK", command=confirm, width=10).pack(pady= (10, 10), ipady=1)
    # A standardised template to create new rows in the NBAAT File Selector Window
    def create_file_selector_row(self, row, label_text, filetypes):

        # Create the label of the row to inform user which file to select
        label = tk.Label(self.root, text=label_text)
        label.grid(row=row, column=0, padx=10, pady=10)

        # Create the entry bar that display the file path for user to view the file they have chosen
        entry = tk.Entry(self.root, width=60, state="readonly") # Entry bar state is set to read-only. Cannot be edited. 
        entry.grid(row=row, column=1, padx=5, pady=10, sticky="nsew")


        # Browse the file system to select the file to insert
        def browse_file():
            file_path = filedialog.askopenfilename(filetypes=filetypes) # Accept only files with the specified filetypes mentioned in the filetypes parameter
            if file_path:
                entry.config(state="normal") # Entry bar state is set to Normal to enable editing.
                entry.delete(0, tk.END) # Delete the existing file selected and the file path displayed on the entry bar
                entry.insert(0, file_path) # Insert the selected file path onto the entry bar. 
                entry.config(state="readonly") # Set entry bar state back to Read-only. 

        # Clear the file that is selected previously
        def clear_file():
            entry.config(state="normal") # Entry bar state is set to Normal to enable editing.
            entry.delete(0, tk.END) # Delete the existing file selected and the file path displayed on the entry bar
            entry.config(state="readonly") # Set entry bar state back to Read-only. 

        # Specifications of the "Browse..." button. Clicking the "Browse..." button will
        # execute the browse_file() function
        browse_button = tk.Button(self.root, text="Browse...", command=browse_file)
        browse_button.grid(row=row, column=2, padx=(10, 0), pady=10)

        # Specification of the "Clear" button. Clicking the "Clear" button will execute the
        # clear_file() function
        clear_button = tk.Button(self.root, text="Clear", command=clear_file)
        clear_button.grid(row=row, column=3, padx=(0, 10), pady=10, ipadx=10)

        return entry

    # Overall specifications for the main NBAAT File Selector GUI window 
    def build_main_gui(self):
        
        # Specifications of the NBAAT File Selector window
        self.root.title("NBAAT File Selector")
        self.root.geometry("800x180")             # Default size of the window when opened
        self.root.minsize(800, 180)               # Minimum window size that can be displayed
        
        # # Make all columns expandable
        for col in range(4):
            self.root.columnconfigure(col, weight=1)

        # Make all rows expandable
        for row in range(3):
            self.root.rowconfigure(row, weight=1)

        # Creating Row 0 - Selecting the Nessus Excel File
        self.nessus_entry = self.create_file_selector_row(
            row=0,
            label_text="Select Nessus CSV File:",
            filetypes=[("Excel files", "*.csv")] # Ensure only excel files can be selected
        )

        # Creating Row 1 - Selecting the BurpSuite XML File
        self.burp_entry = self.create_file_selector_row(
            row=1,
            label_text="Select BurpSuite XML File:",
            filetypes=[("XML files", "*.xml")] #Ensure only XML Formatted files can be selected.
        )
    
        # Creating Row 2 - Creating "Back" and "Generate Annex B Report" buttons

        # Return user to the Project Name Window (back_to_project_name_popup function)
        self.back_button = tk.Button(self.root, text="Back", command=self.back_to_project_name_popup)
        self.back_button.grid(row=2, column=0, columnspan=2, padx=10, pady=20, ipadx=10)

        # Generate Annex B Report after the required files are selected (generate_report function)
        self.generate_button = tk.Button(self.root, text="Generate Annex B Report", command=self.generate_report)
        self.generate_button.grid(row=2, column=1, columnspan=3, padx=10, pady=20)
    
    # Return to the Project Name Popup Page
    def back_to_project_name_popup(self):
        self.root.withdraw()  # Hide the main NBAAT selector window again
        self.show_project_name_popup() # Rebuild the Project Name Popup Window

    # Generate the Annex B report
    def generate_report(self):
        nessus = self.nessus_entry.get().strip()
        burp = self.burp_entry.get().strip()

        # Display the folllowing Messagebox responses from the various conditions below when "Generate" Button is clicked
        
        if not nessus and not burp:     # if neither files are selected
            messagebox.showwarning("No Files Selected", "Please select at least one file - Nessus Excel/BurpSuite XML file.")
        
        else:
            # Create the default filename using project name and timestamp
            timestamp = time.strftime("%Y%m%d_%H%M%S")
            official_project_name = self.name.replace(" ", "_")
            default_filename = f"{official_project_name}_{timestamp}_Annex_B_Report.xlsx"

            # Ask user where to save the file
            save_path = filedialog.asksaveasfilename(
                defaultextension=".xlsx",
                initialfile=default_filename,
                filetypes=[("Excel files", "*.xlsx")],
                title="Save Report As"
            )

            if save_path:
                    # TODO: Replace this placeholder with real file generation logic
                    if nessus:
                        wb = convert.nessus_convert(nessus, save_path)  # Call the nessus_convert function from the convert module to generate the report

                        if burp:
                            wb = baat.generate_burp_report(burp, wb, False)
                    else:
                        wb = baat.generate_burp_report(burp, None, True)

                    wb.save(save_path)

                    messagebox.showinfo("Report Generated", f"Report saved to:\n{save_path}")
                    self.root.destroy()
                    sys.exit()
            else:
                    messagebox.showinfo("Cancelled", "Report generation cancelled.")

#Launch the application
if __name__ == "__main__":
    root = tk.Tk()  #Create the NBAAT File Selector main application window
    app = FileSelectorApp(root)
    root.mainloop()
