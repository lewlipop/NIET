import xml.etree.ElementTree as ET
from openpyxl import Workbook
from openpyxl.styles import Alignment, PatternFill
from openpyxl.worksheet.datavalidation import DataValidation
from openpyxl.formatting.rule import FormulaRule
from tkinter import Tk, Toplevel, filedialog, messagebox, Label, Entry, Button, StringVar, Frame
from tkinter.simpledialog import askstring
from bs4 import BeautifulSoup
from urllib.parse import unquote
from excel_standard_styles import HEADER_FONT, CENTER_ALIGN, TOP_ALIGN, ALL_BORDERS_STYLES #Import the header font, borders, center and top alignment styles from excel_standard_styles.py
from results_summary import add_summary_to_excel #Import add_summary_to_excel() function from results_summary.py
from datetime import datetime
import sys
import html
import re

#Initialise GUI
# root = Tk()
# root.withdraw()

# # Prompt user with a proper input window for project name
# def get_project_name(root):
#     def on_submit():
#         name = entry.get().strip()
#         if not name:
#             messagebox.showwarning("No Project Name specified", "Project name is required.")
#         # Check the Project Name for any invalid characters
#         elif re.search(r'[\\/:*?"<>|]', name):
#             messagebox.showerror("Invalid Project Name", "Please ensure your project name does not contain these invalid characters: \\ / : * ? \" < > |")
#         else:
#             input_window.project_name = name
#             input_window.destroy()

#     input_window = Toplevel(root)
#     input_window.title("Enter Audit Project Name") # Title of the window
#     input_window.geometry("350x150")             # Default Size of the window when opened
#     input_window.minsize(350, 150)               # Minimum window size that can be displayed
#     input_window.grab_set()

#     Label(input_window, text="Please enter Audit Project Name:").pack(pady=10) # Label within the Audit Project Name window
#     entry = Entry(input_window, width=30) # Entry bar within the window to fill up the Audit Project Name
#     entry.pack(pady=5)
#     entry.focus()

#     Button(input_window, text="OK", command=on_submit, width=10).pack(pady= (10, 10), ipady=1) # Specifications of the OK button

#     input_window.project_name = None
#     root.wait_window(input_window)  # Wait for window to close before continuing

#     return input_window.project_name

# # Call get_project_name function to obtain the Audit Project Name
# project_name = get_project_name(root)

# # If user close the Audit Project Name window
# if (project_name == None):
#     messagebox.showinfo("Cancelled", "No audit project name selected. Exiting.")
#     sys.exit()

# # Select the Burp XML File
# file_path = filedialog.askopenfilename(
#     title="Select Burp Suite XML File",
#     filetypes=[("XML Files", "*.xml")]
# )

# # Show message box response and exit program when no file is selected 
# if not file_path:
#     messagebox.showinfo("Cancelled", "No file selected. Exiting.")
#     sys.exit()

# # Generate timestamp string. Allow user to choose the location to save the Excel File
# timestamp = datetime.now().strftime("%d%m%Y_%H%M%S")
# default_filename = f"{project_name}_{timestamp}_Burp_Scan_Results.xlsx" # File is saved in this file format - with the project name and current timestamp

# #Output path of the saved file follow the default_filename variable specified above
# output_path = filedialog.asksaveasfilename(
#     title = "Save Excel File As",
#     defaultextension=".xlsx",
#     filetypes=[("Ëxcel Files", "*.xlsx")],
#     initialfile=default_filename
# )

# # Show message box response and exit program when no location is selected for saving the file 
# if not output_path:
#     messagebox.showinfo("Cancelled", "No save location selected. Exiting.")
#     sys.exit()

# Format the header row of the excel sheet
def header_formatting(ws, headers, header_fill):
    
    # Append Headers into Excel Sheet
    ws.append(headers)
    # Apply formatting to header row
    for col in range(1, len(headers) + 1):
        cell = ws.cell(row=1, column=col)
        cell.fill = header_fill
        cell.font = HEADER_FONT
        cell.alignment = CENTER_ALIGN

# Clean up the raw data obtained from the XML File stored for each vulnerability finding and its solution
def clean_html(html_text):
    if not html_text:
        return ""

    # Parse the XML raw Data into BeautifulSoup
    soup = BeautifulSoup(html_text, "html.parser") 

     # Convert <li> tags into bullet points and newlines
    for li in soup.find_all("li"):
        bullet_text = "\n• " + li.get_text().strip() + "\n"
        li.insert_before(bullet_text)
        li.decompose()

    # Remove all other tags
    for tag in soup.find_all(True):
        tag.unwrap()

    # Get text, preserving structure
    text = soup.get_text()

    # Decode HTML entities and URL encoding
    text = html.unescape(unquote(text))

    # Normalize space but keep line breaks before bullets
    text = re.sub(r'[ \t]+', ' ', text)  # collapse spaces/tabs
    text = re.sub(r'\n\s*•', '\n•', text)       # clean spaces before bullets
    text = re.sub(r'(?<!\n)\•', '\n\n•', text)    # ensure bullets start on a new line

    return text.strip()

# Insert Border Design in the Excel Sheet
def border_design(ws):
    for row in ws.iter_rows(min_row=1, max_row=ws.max_row, min_col=ws.min_column, max_col=ws.max_column):
        for cell in row:
            cell.border = ALL_BORDERS_STYLES

# Add dropdowns only to rows where status is not "N.A."
def add_status_dropdown_options(ws, status_options):
    dv = DataValidation(type="list", formula1=f'"{",".join(status_options)}"', allow_blank=True)
    ws.add_data_validation(dv)
    for row in range(2, ws.max_row + 1):
        status_cell = ws.cell(row=row, column=7)
        if status_cell.value != "N.A.":
            dv.add(status_cell)

# Add colours for "Status" option in dropdown menu of "Status" column for conditional formatting
def add_status_colours(ws, status_colours, headers):
    status_col_letter = ws.cell(row=1, column=7).column_letter
    # Add conditional formatting rules for each status to color entire row dynamically
    for status, fill in status_colours.items():
        formula = f'${status_col_letter}2="{status}"'  # Excel formula (applied relative to each row)
        ws.conditional_formatting.add(
            f'A2:{ws.cell(row=ws.max_row, column=len(headers)).column_letter}{ws.max_row}',
            FormulaRule(formula=[formula], fill=fill)
        )

def generate_burp_report(burp, wb=None, standalone=False):
    try:
        tree = ET.parse(burp)
        root = tree.getroot()

        #Create Excel workbook
        if not wb:
            wb= Workbook()
        ws = wb.create_sheet(title="BurpSuite Scan Results")

        # Mapping to sort by severity level (higher priority gets lower sort value)
        severity_priority = {
        "High": 1,
        "Medium": 2,
        "Low": 3,
        "Information": 4
        }

        # Define Headers & its colours for the "BurpSuite Scan Results" excel sheet
        headers = ["Host", "Path", "Issue Type", "Severity", "Vulnerability Findings", "Solution", "Status", 
                "Remediation Plan", "Ëstimated Date of Completion", "Remarks", "Category"]
        header_fill = PatternFill(start_color="FFC000", end_color="FFC000", fill_type="solid")  # Orange

        #Dropdown options for "Status" column (column 7)
        status_options = ['Open', 'Follow Up', 'Closed', 'Declared']

        # Colours for each "Status" option in dropdown menu of "Status" column for conditional formatting
        status_colours = {
            "Open": PatternFill(start_color="FFC7CE", end_color="FFC7CE", fill_type="solid"),
            "Follow Up": PatternFill(start_color="FFEB9C", end_color="FFEB9C", fill_type="solid"),
            "Closed": PatternFill(start_color="82F073", end_color="82F073", fill_type="solid"),
            "Declared": PatternFill(start_color="8DB5F0", end_color="8DB5F0", fill_type="solid"),
        }

        # Format Header Row
        header_formatting(ws, headers, header_fill)

        # Collect and store all the row values in data_rows list.
        data_rows = []
        
        # Obtain values corresponding to each header column from the XML File and append it row by row.
        for issue in root.findall('.//issue'):
            host = issue.findtext('host', '')
            path = issue.findtext('path', '')
            issue_type = issue.findtext('name', '')
            severity = issue.findtext('severity', '')

            vuln_findings_raw = issue.findtext('issueDetail', '')
            solution_raw = issue.findtext('remediationBackground', '')
            solution = clean_html(solution_raw)

            # If severity level is Information and there are no vuln findings, set "Vulnerability Findings", "Status" and "Category" value to "N.A", 
            if severity == "Information" and vuln_findings_raw == "":
                row = [host, path, issue_type, severity, "N.A", solution, "N.A.", "", "", "", "N.A."]
            
            # If severity level is Information but there are vuln findings found, set "Status", and "Category" value to "N.A".
            elif severity == "Information" and vuln_findings_raw != "":
                vuln_findings = clean_html(vuln_findings_raw)
                row = [host, path, issue_type, severity, vuln_findings, solution, "N.A.", "", "", "", "N.A."]
            else:
            # Otherwise, set the "Status" value to "Open", and the "Vulnerability Findings" value to "Vulnerability" for the row,
                vuln_findings = clean_html(vuln_findings_raw)
                row = [host, path, issue_type, severity, vuln_findings, solution, "Open", "", "", "", "Web-based Vulnerabilities"]

            # Append the rows into data_rows list first
            data_rows.append(row)

        # Sort the row values within data_rows list by severity using the mapping
        data_rows.sort(key=lambda x: severity_priority.get(x[3], 5))  # x[3] = severity

        # Append the sorted rows to worksheet
        for row in data_rows:
            ws.append(row)
            
        # Auto-size columns (except Column E and Column F)
        for col in ws.columns:
            max_length = 0
            col_letter = col[0].column_letter
            col_number = col[0].column

            # Override column width and wrap text for Column E and F
            if col_letter == "E" or col_letter == "F":
                ws.column_dimensions[col_letter].width = 50 #Set column width for E and F to 50
                for row in range(2, ws.max_row + 1):
                    cell = ws.cell(row=row, column=col_number)
                    if cell.value != "N.A":
                        cell.alignment = TOP_ALIGN # Wrap text for cells in Column E and F if the cell value is not "N.A."
                    else: 
                        cell.alignment = CENTER_ALIGN #Otherwise, if the cell value is "N.A", center align Column E and Column F.
            else:
                # Apply center alignment to selected columns below
                for col_number in [1, 2, 3, 4, 7, 9, 11]:
                    for row in range(2, ws.max_row + 1):
                        ws.cell(row=row, column=col_number).alignment = CENTER_ALIGN
                
                # Apply top alignment to selected columns below
                for col_number in [8, 10]:
                    for row in range(2, ws.max_row + 1):
                        ws.cell(row=row, column=col_number).alignment = TOP_ALIGN

                #Autosize Columns (except Column E and Column F)                    
                for cell in col:
                    try:
                        if cell.value:
                            max_length = max(max_length, len(str(cell.value)))
                    except:
                        pass
                ws.column_dimensions[col_letter].width = max_length + 2
        
        # Insert Border Design in "BurpSuite Scan Results" Excel Sheet
        border_design(ws)

        # Add dropdowns and its options only to rows where status is not "N.A."
        add_status_dropdown_options(ws, status_options)
        
        # Add colours for "Status" option in dropdown menu of "Status" column for conditional formatting
        add_status_colours(ws, status_colours, headers)

        
        # Add a new sheet called "Vulnerabilities Summary Count" to summarise the number of vulnerabiltiies recorded via severity. (PASS workbook object to function)
        if standalone:
            add_summary_to_excel(wb)

        return wb
        #Save to user-defined location
        # wb.save(output_path)
        messagebox.showinfo("Success", f"Results saved to:\n{output_path}")

    except ET.ParseError:
        messagebox.showerror("XML Error", "The XML file could not be parsed.")

    except Exception as e:
        messagebox.showerror("Unexpected Error", f"An error occurred:\n{str(e)}")