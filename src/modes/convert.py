import json
import re
import csv
from openpyxl import Workbook
from openpyxl.worksheet.table import Table, TableStyleInfo
from openpyxl.worksheet.datavalidation import DataValidation
from openpyxl.styles import PatternFill, Font, Border, Side
from openpyxl.formatting.rule import FormulaRule
from openpyxl.utils import get_column_letter

# Module-level constant for IP matching.
IP_REGEX = None


def remove_duplicates(rows, keys):
    """
    Remove duplicate rows from a list of dictionaries.
    Duplicates are defined as rows that have identical values for every key in 'keys'.
    """
    unique_rows = []
    seen = set()
    for row in rows:
        key_tuple = tuple(row.get(key, "").strip() for key in keys)
        if key_tuple not in seen:
            seen.add(key_tuple)
            unique_rows.append(row)
    return unique_rows


def create_table_and_style(sheet, table_name, config=None):
    """
    Create an Excel table on the given sheet and apply header fill, font, and border styles.
    If the sheet has only a header row (no data), a dummy row is added so the table range is valid.
    """
    if config is None:
        config = {}
    
    table_style = config.get("table_style", "TableStyleMedium9")
    show_first_column = config.get("show_first_column", False)
    show_last_column = config.get("show_last_column", False)
    show_row_stripes = config.get("show_row_stripes", False)
    show_column_stripes = config.get("show_column_stripes", False)
    header_fill = config.get("header_fill", "A5A5A5")
    header_fill_type = config.get("header_fill_type", "solid")
    header_font_color = config.get("header_font_color", "000000")
    cell_fill = config.get("cell_fill", "ffffff")
    cell_fill_type = config.get("cell_fill_type", "solid")
    cell_border = config.get("cell_border", "thin")
    cell_font_color = config.get("cell_font_color", "000000")

    if sheet.max_row < 2:
        # Insert a dummy row with empty strings for each column
        sheet.append([""] * sheet.max_column)
    
    max_row = sheet.max_row
    max_col = sheet.max_column
    

    # A1 --> the top-left corner of the sheet
    # get_column_letter(max_col) → converts a column number (e.g. 5) into Excel letters (“E”)
    # max_row → the last row number with data

    table_range = f"A1:{get_column_letter(max_col)}{max_row}" 
    
    # removes spaces from the table_name value so Excel will accept it as a valid table identifier on the Dipslay Name tab.
    tab = Table(displayName=table_name.replace(" ", ""), ref=table_range) 


    style = TableStyleInfo(name=table_style, showFirstColumn=show_first_column,
                           showLastColumn=show_last_column, showRowStripes=show_row_stripes, showColumnStripes=show_column_stripes)
    tab.tableStyleInfo = style
    sheet.add_table(tab)
    
    thin_border = Border(left=Side(style=cell_border), right=Side(style=cell_border),
                        top=Side(style=cell_border), bottom=Side(style=cell_border))
    
    header_fill = PatternFill(start_color=header_fill, end_color=header_fill, fill_type=header_fill_type)
    for cell in sheet[1]:
        cell.border = thin_border
        cell.fill = header_fill
        cell.font = Font(color=header_font_color)
        
    cell_fill = PatternFill(start_color=cell_fill, end_color=cell_fill, fill_type=cell_fill_type)
    for row in sheet.iter_rows(min_row=2, max_row=max_row, min_col=1, max_col=max_col):
        for cell in row:
            cell.border = thin_border
            cell.fill = cell_fill
            cell.font = Font(color=cell_font_color)
            

def write_csv_sheet(sheet, dataset, csv_header, sheet_options, extract_config=None):
    global COUNT, IP_REGEX
    if extract_config is None:
        extract_config = {}
    
    headers_to_remove = [h.lower() for h in sheet_options.get("headers_to_remove", [])]
    csv_header_no = [col for col in csv_header if col.lower() not in headers_to_remove]
    
    # Build the new header.
    new_header = []
    for col in csv_header_no:
        new_header.append(col)
        if col.lower() == sheet_options.get("insert_mapping_columns_after", "Risk").lower():
            if sheet_options.get("mapping_columns", None) is not None:
                new_header.extend(sheet_options.get("mapping_columns", []))
    
    if extract_config.get("extract_column_name", None) is not None:
        new_header.extend([extract_config.get("extract_column_name")])
    
    additional_columns = sheet_options.get("additional_columns", None)
    if additional_columns is not None:
        new_header.extend(additional_columns.keys())
    
    sheet.append(new_header)
    
    # Process each row in the dataset.
    for row in dataset:
        base_row = []
        for col in csv_header_no:
            base_row.append(row.get(col, ""))
            if col.lower() == sheet_options.get("insert_mapping_columns_after", "Risk").lower():
                host_val = row.get(sheet_options.get("host_column_name", "Host"), "").strip()
                
                if IP_REGEX.match(host_val):
                    mapping_val_row = sheet_options.get("ip_match", [0, 0, 1, 0, 0, 0])[:]
                else:
                    mapping_val_row = sheet_options.get("not_ip_match", [1, 0, 0, 0, 0, 0])[:]
                    
                for i, val in enumerate(mapping_val_row):
                    if val == 1:
                        mapping_val_row[i] = host_val
                base_row.extend(mapping_val_row)
                
        # If extra processing is requested, create one row per extra value.
        if extract_config.get("extract_column_name", None) is not None:
            extra_values = extract_information(row, extract_config)
            for extra in extra_values:
                extra_row = base_row[:]
                extra_row.extend([extra, *[value for value in additional_columns.values()]])
                sheet.append(extra_row)
        else:
            base_row.extend([value for value in additional_columns.values()])
            sheet.append(base_row)


def add_lookup_formulas(sheet, hosts_sheet, sheet_options):
    """
    Insert lookup formulas in the host-lookup columns of the given sheet using data from the Hosts sheet.
    """
    # Extract configuration from sheet_options
    mapping_cols = sheet_options.get("mapping_columns", [])
    mapping_formulas = sheet_options.get("mapping_columns_formula", {})
    
    # Build a dictionary mapping each configured column name to its column index in the sheet
    headers = [cell.value for cell in sheet[1]]
    col_indices = {}
    for col in mapping_cols:
        try:
            col_indices[col] = headers.index(col) + 1
        except ValueError:
            # Skip if the expected column is not found
            continue

    # Determine the number of rows in the Hosts sheet (to define lookup ranges)
    host_rows = hosts_sheet.max_row
    if host_rows < 2:
        return

    # Process each data row in the sheet
    for i in range(2, sheet.max_row + 1):
        # Build a dynamic replacements dictionary for the current row.
        # For each mapping column, we create keys like {ColumnName_cell} and {columnname_cell}
        # to handle different naming conventions in the formula templates.
        replacements = {"host_rows": str(host_rows), "hosts_table_name": sheet_options.get("hosts_table_name", "Hosts")}
        for col in mapping_cols:
            if col in col_indices:
                cell_ref = f"{get_column_letter(col_indices[col])}{i}"
                replacements[f"{col}_cell"] = cell_ref
                replacements[f"{col.lower()}_cell"] = cell_ref  # Cover lower-case placeholder

        # Loop over each formula in the config and apply substitutions.
        # The key in mapping_formulas is the target column where the formula should be placed.
        for target_col, formula_template in mapping_formulas.items():
            if target_col not in col_indices:
                continue  # Skip if the target column isn't in the sheet
            formula = formula_template
            # Replace every placeholder in the formula with the dynamic cell references
            for placeholder, value in replacements.items():
                formula = formula.replace(f"{{{placeholder}}}", value)
            # Assign the computed formula to the appropriate cell in the target column
            sheet.cell(row=i, column=col_indices[target_col]).value = formula

def add_validation(sheet, values, header:str, default_value:str=None):
    """
    Add data validation for the given column on the given sheet.
    """
    headers = [cell.value for cell in sheet[1]]
    try:
        category_idx = headers.index(header) + 1
    except ValueError:
        return
    max_row = sheet.max_row
    if max_row < 2:
        return
    # Excel requires the list to be under 255 chars, so join with comma
    dv = DataValidation(type="list", formula1=f'"{",".join(values)}"', allow_blank=False)
    dv.error = 'Select a value from the list'
    dv.errorTitle = 'Invalid Entry'
    dv_range = f"{get_column_letter(category_idx)}2:{get_column_letter(category_idx)}{max_row}"
    sheet.add_data_validation(dv)
    dv.add(dv_range)

    # Set default value if provided
    if default_value is not None and default_value in values:
        for row in range(2, max_row + 1):
            cell = sheet.cell(row=row, column=category_idx)
            if not cell.value:  # Only set if cell is empty
                cell.value = default_value# Set default value if provided

def add_status_validation(sheet, config=None):
    """
    Add data validation for the "Status" column on the given sheet.
    Acceptable values: "-", "Open", "Follow up", "Closed".
    """
    if config is None:
        config = {}
        
    DEFAULT_STATUS_MAP = {
        "-": "ffffff",
        "Open": "FF0000",
        "Follow up": "FFC7CE",
        "Closed": "FFEB9C",
        "Declared": "24FC03"
    }
        
    status_map = config.get("status_map", DEFAULT_STATUS_MAP)
    
    headers = [cell.value for cell in sheet[1]]
    try:
        status_idx = headers.index("Status") + 1
    except ValueError:
        return
    max_row = sheet.max_row
    # Only apply data validation if there are data rows.
    if max_row < 2:
        return
    dv = DataValidation(type="list", formula1=f'"{",".join(status_map.keys())}"', allow_blank=False)
    dv.error = 'Select a value from the list'
    dv.errorTitle = 'Invalid Entry'
    dv_range = f"{get_column_letter(status_idx)}2:{get_column_letter(status_idx)}{max_row}"
    sheet.add_data_validation(dv)
    dv.add(dv_range)


def add_conditional_formatting(sheet, config=None):
    """
    Add conditional formatting to the "Status" column.
    Applies a red fill for "Open" and an orange fill for "Follow up".
    """
    if config is None:
        config = {}
        
    DEFAULT_STATUS_MAP = {
        "-": "ffffff",
        "Open": "FFC7CE",
        "Follow up": "FFEB9C",
        "Closed": "82F073",
        "Declared": "8DB5F0"
    }
        
    status_map = config.get("status_map", DEFAULT_STATUS_MAP)
    status_fill_type = config.get("status_fill_type", "solid")
    
    headers = [cell.value for cell in sheet[1]]
    try:
        status_idx = headers.index("Status") + 1
    except ValueError:
        return
    max_row = sheet.max_row
    if max_row < 2:
        return
    data_range = f"A2:{get_column_letter(sheet.max_column)}{max_row}"
    
    for status, color in status_map.items():
        formula = f'=${get_column_letter(status_idx)}2="{status}"'
        fill = PatternFill(start_color=color, end_color=color, fill_type=status_fill_type)
        sheet.conditional_formatting.add(data_range, FormulaRule(formula=[formula], fill=fill))


def extract_information(row, config):
    regex_flags = re.IGNORECASE if config.get("case_insensitive") else 0

    # Process lookup_columns to extract lookup values
    lookup_col_patterns = config.get("lookup_columns", [])
    compiled_lookup_col_patterns = [re.compile(pat, regex_flags) for pat in lookup_col_patterns]

    lookup_values = []
    for col_name, value in row.items():
        for pattern in compiled_lookup_col_patterns:
            if pattern.search(col_name):
                lookup_values.append(value.strip())
                break

    # Determine OS type based on lookup values
    for os_type in ["linux", "windows"]:
        lookup_patterns = config.get(os_type, {}).get("lookup_values", {})
        compiled_lookup_patterns = [re.compile(pat, regex_flags) for pat in lookup_patterns]

        if any(any(p.search(val) for p in compiled_lookup_patterns) for val in lookup_values):
            user_type = os_type
            break
    else:
        return []
    


    # Extract relevant text from specified columns
    extract_col_patterns = config.get("extract_columns", [])
    compiled_extract_col_patterns = [re.compile(pat, regex_flags) for pat in extract_col_patterns]

    extracted_text_parts = []
    for col_name, value in row.items():
        for pattern in compiled_extract_col_patterns:
            if pattern.search(col_name):
                extracted_text_parts.append(value.strip())
                break
    extracted_text = "\n".join(extracted_text_parts)

    # Process OS-specific extraction patterns
    extraction_conf = config.get(user_type, {}).get("extraction", {})
    user_regexes = extraction_conf.get("regex", [])
    compiled_user_regexes = [re.compile(pat, regex_flags) for pat in user_regexes]

    exclude_patterns = extraction_conf.get("exclude", [])
    compiled_exclude_patterns = [re.compile(pat, regex_flags) for pat in exclude_patterns]

    results = []
    for line in extracted_text.splitlines():
        line = line.strip()
        if not line or any(p.search(line) for p in compiled_exclude_patterns):
            continue
        for regex in compiled_user_regexes:
            match = regex.match(line)
            if match:
                extracted_value = match.group(1).strip() if match.groups() else line
                results.append(extracted_value)
                break

    return results


def hide_and_autowidth_columns(sheet, allowed_columns, auto_columns):
    """
    Hide all columns not listed in allowed_columns.
    For columns in auto_columns, adjust the width based on the maximum cell length.
    """
    header = [cell.value for cell in sheet[1]]
    for idx, col_name in enumerate(header, start=1):
        col_letter = get_column_letter(idx)
        if col_name not in allowed_columns:
            sheet.column_dimensions[col_letter].hidden = True
        elif col_name in auto_columns:
            max_length = 0
            for cell in sheet[col_letter]:
                if cell.value:
                    max_length = max(max_length, len(str(cell.value)))
            sheet.column_dimensions[col_letter].width = max_length + 2

def create_summary_sheet(wb):
    """
    Create a 'Summary' sheet with "Non-Compliance" and "Vulnerability" sections.
    Categories are fixed in column A, other columns are left empty.
    The header row and the 'Vulnerability' section row are styled like other sheet headers.
    The 'Number of findings' column is filled with formulas.
    """
    non_compliance = [
        "Missing OS or Software Patch",
        "Inadequate Hardening",
        "Unauthorised Open Port or Service or Devices",
        "Unauthorised Software or File",
        "Unauthorised Network Shared Drive or Folder",
        "Excessive Privileged Account",
        "Approved ACMs not Implemented"
    ]
    vulnerability = [
        "End-of-Life OS or software",
        "Software or Firmware Vulnerabilities",
        "Web-Based Vulnerabilities"
    ]
    headers = [
        "Non-Compliance",
        "Highest Cyber Severity",
        "Number of audited servers/devices affected",
        "Status",
        "Number of findings"
    ]
    sheet = wb.create_sheet("Summary")
    sheet.append(headers)

    # --- Add Non-Compliance categories (rows 2-8) ---
    for cat in non_compliance:
        sheet.append([cat] + [""] * (len(headers) - 1))

    # --- Vulnerability section header (row 9) ---
    sheet.append(["Vulnerability"] + [""] * (len(headers) - 1))

    # --- Add Vulnerability categories (rows 10-12) ---
    for cat in vulnerability:
        sheet.append([cat] + [""] * (len(headers) - 1))

    # --- Style header and Vulnerability row like other sheet headers ---
    header_fill = PatternFill(start_color="A5A5A5", end_color="A5A5A5", fill_type="solid")
    header_font_color = "000000"
    thin_border = Border(
        left=Side(style="thin"),
        right=Side(style="thin"),
        top=Side(style="thin"),
        bottom=Side(style="thin")
    )

    # Style the header row (row 1)
    for cell in sheet[1]:
        cell.border = thin_border
        cell.fill = header_fill
        cell.font = Font(color=header_font_color, bold=True)

    # Style the Vulnerability section row (row 9)
    for cell in sheet[9]:
        cell.border = thin_border
        cell.fill = header_fill
        cell.font = Font(color=header_font_color, bold=True)

    # Define dictionary for sheets indicating column letter for category, status & IP (HARDCODED)
    # Change if there are new columns added in the future

    col_dict = {
        "Compliance": ("AK", "AJ", "H"),
        "Vulnerabilities": ("AK", "AJ", "H"),
        "Open Ports": ("AK", "AJ", "H"),
        "Users": ("AL", "AK", "H"),
        "Installed Software": ("AL", "AK", "H"),
        "BurpSuite Scan Results": ("K", "G", "A")
    }

    # --- Insert formulas for "Number of findings" (column E) ---
    # Mapping: summary row index (1-based) -> (sheet, category)
    findings_map = {
        2:  ("Compliance", "Missing OS or Software Patch"),
        3:  ("Compliance", "Inadequate Hardening"),
        4:  ("Open Ports", "Unauthorised Open Port or Service or Devices"),
        5:  ("Installed Software", "Unauthorised Software or File"),
        6:  ("Compliance", "Unauthorised Network Shared Drive or Folder"),
        7:  ("Users", "Excessive Privileged Account"),
        8:  ("Compliance", "Approved ACMs not Implemented"),
        10: ("Vulnerabilities", "End-of-Life OS or software"),
        11: ("Vulnerabilities", "Software or Firmware Vulnerabilities"),
        12: ("BurpSuite Scan Results", "Web-Based Vulnerabilities"),  # No formula, leave blank
    }

    # Formula for counting findings
    for row_idx, (sheet_name, cat_value) in findings_map.items():
        formula = (
            f'=SUMPRODUCT(--(\'{sheet_name}\'!${col_dict[sheet_name][0]}$2:${col_dict[sheet_name][0]}$1000="{cat_value}"),'
            f'--(\'{sheet_name}\'!${col_dict[sheet_name][1]}$2:${col_dict[sheet_name][1]}$1000<>"Declared"),'
            f'--(\'{sheet_name}\'!${col_dict[sheet_name][1]}$2:${col_dict[sheet_name][1]}$1000<>"Closed"))'
        )
        sheet.cell(row=row_idx, column=5).value = formula

    for row_idx, (sheet_name, cat_value) in findings_map.items():
        ip_col = col_dict[sheet_name][2]
        cat_col = col_dict[sheet_name][0]
        # Build the array formula string as plain text (no =, no $)
        formula = (
            f"SUM(--(FREQUENCY("
            f"IF('{sheet_name}'!{cat_col}2:{cat_col}1000=\"{cat_value}\", "
            f"MATCH('{sheet_name}'!{ip_col}2:{ip_col}1000, '{sheet_name}'!{ip_col}2:{ip_col}1000, 0)), "
            f"ROW('{sheet_name}'!{ip_col}2:{ip_col}1000)-ROW('{sheet_name}'!{ip_col}2)+1"
            f")>0))"
        )
        # Insert as plain text (not a formula)
        sheet.cell(row=row_idx, column=3).value = formula
    
    add_status_validation(sheet)
    add_validation(sheet, [
                "High",
                "Medium",
                "Low",
                "-"
            ], "Highest Cyber Severity", "-")
    # create_table_and_style(sheet, "Summary", config.get("table", {}))



def add_risk_font_formatting(sheet, sheet_options):
    """
    Add conditional formatting rules to change the font color based on the risk level.
    """
    headers = [cell.value for cell in sheet[1]]
    try:
        idx = headers.index(sheet_options.get("text_format_column", "Risk")) + 1
    except ValueError:
        return
    max_row = sheet.max_row
    if max_row < 2:
        return
    col_letter = get_column_letter(idx)
    data_range = f"{col_letter}2:{col_letter}{max_row}"
    for val, color in sheet_options.get("text_format", {}).items():
        rule = FormulaRule(formula=[f'=${col_letter}2="{val}"'], font=Font(color=color))
        sheet.conditional_formatting.add(data_range, rule)


def nessus_convert(csv_filename: str, excel_filename: str, logger=None, software_exclusion_keywords=None, flags=None, config_path=None):
    """
    Convert the given CSV file into an Excel workbook.
    Six sheets are created (in order):
      1. "Hosts": Unique hosts from the CSV with columns "Hostname", "IP", "OS".
      2. "Vulnerabilities": Processed CSV rows with Risk in {"None","Low","Medium","High","Critical"}.
         After removing "Host" and "Plugin Output", immediately after "Risk" insert six new host-lookup columns:
         "Hostname_original", "Hostname", "IP_original", "IP", "OS_original", "OS", then append "Status" (set to "Open")
         and "Remarks".
      3. "Compliance": Processed similarly for rows with Risk in {"FAILED","WARNING"}.
      4. "Open Ports": Processed similarly for rows where Name equals "Netstat Portscanner (SSH)".
      5. "Users": For rows where Name is "Linux User List Enumeration" or "Enumerate Users via WMI",
         extract individual users from "Plugin Output" and for each create a new row. The header is built as above,
         then extra columns "User", "Status", "Remarks" are appended. Additionally, the six host-lookup columns
         are included and filled with structured formulas.
      6. "Installed Software": For rows where Name contains "Software Enumeration" (case insensitive)
         and does not contain any exclusion keyword (default: ["startup", "start-up", "os"]),
         for each host (only the first matching row per host is kept) the "Plugin Output" is split (by newlines)
         and each extracted line is written as a new row. The header is built as above but with extra columns
         "Installed Programs", "Status", "Remarks". Again, the six host-lookup columns are included and filled.
    
    All CSV-derived sheets are converted into Excel tables with header cells styled with a solid fill (RGB A5A5A5)
    with black text and full thin borders. Data validation is added so that the "Status" column only accepts
    "-", "Open", "Follow up", or "Closed". In Vulnerabilities, Compliance and Open Ports the host-lookup columns
    are filled with lookup formulas (using A1-style references to the Hosts sheet). For Users and Installed Software,
    the host-lookup columns are present and then overwritten with structured reference formulas.
    
    Finally, the visible columns are limited (the rest are hidden) as follows:
         - Hosts: ["Hostname", "IP", "OS"]
         - Vulnerabilities: ["Risk", "Hostname", "IP", "OS", "Name", "Synopsis", "Description", "Solution", "See Also", "Status", "Remarks"]
         - Compliance: ["Risk", "Hostname", "IP", "OS", "Name", "Description", "Solution", "See Also", "Status", "Remarks"]
         - Open Ports: ["Hostname", "IP", "OS", "Protocol", "Port", "Status", "Remarks"]
         - Users: ["Hostname", "IP", "OS", "User", "Status", "Remarks"]
         - Installed Software: ["Hostname", "IP", "OS", "Installed Programs", "Status", "Remarks"]
    """
    global IP_REGEX

    """
    If a config file path is provided, it reads it (JSON).
    Extracts "excel_config" from it.
    Merges it with a default config (so missing keys get defaults).
    Otherwise, uses defaults only.
    """

    if config_path:
        with open(config_path, "r") as f:
            config = json.load(f).get("excel_config", {}) # deserializes a JSON document from a file-like object and returns a corresponding Python object
            config = {**generate_default_config(), **config}
    else:
        config = generate_default_config()


    """
    The setdefault() method returns the value of the item with the specified key.
    If the key does not exist, insert the key, with the specified value,
    """
    # If a list of software_exclusion_keywords is given, they are added to the “installed_software” sheet’s filter_exclude list.
    
    if software_exclusion_keywords is not None:
        config.setdefault("sheets", {}).setdefault("installed_software", {}).setdefault("filter_exclude", []).extend(software_exclusion_keywords)

    """
    re.compile() pre-compiles a regular expression so Python doesn’t have to re-process the pattern every time you use it.
    This regex matches:
    - Valid IPv4 addresses (0–255 in each octet)
    - IPv4 addresses that include wildcard segments using X or x

    get() method returns the value of the item with the specified key.
    If the specified key does not exist, return a default value.
    """
    # Defines a global regex to match IPv4 addresses.
    # Uses the one from the config, or a default that allows X placeholders (like 192.168.X.X).

    IP_REGEX = re.compile(config.get("ip_regex", r"^((25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d|[Xx]{1,3})\.){3}(25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d|[Xx]{1,3})$"))

    hosts_set = set()
    try:
        with open(csv_filename, newline="", encoding="utf-8") as csvfile:

            # Opens the CSV.

            reader = csv.DictReader(csvfile)         # string describing the object's type, internal configuration (dialect), and memory address.
            csv_header = reader.fieldnames           # retrieve a list of the column headers
            rows = list(reader)                     #  iterates through the entire csv.DictReader object and consumes all its data, returning a complete list of dictionaries, where each dictionary represents a row from the CSV file. 


            # If enabled, removes duplicate rows (via a helper function).
            if config.get("remove_duplicates", True):
                rows = remove_duplicates(rows, csv_header)

            

            """
            # Prepares an empty list for each configured “sheet”.

            config.get("sheets", {})
            → Looks for the key "sheets" inside the config dictionary.
            → If "sheets" doesn’t exist, it returns an empty dictionary {} (the default value).

            .values()
            → Returns all the values from that "sheets" dictionary (not the keys).
            """

            sheets = {sheet_name.get("sheet_name"): [] for sheet_name in config.get("sheets", {}).values()} 
            
            # Collects hostnames or IPs into a hosts_set (unique).
            for row in rows:
                host_val = row.get(config.get("host_column_name", "Host"), "").strip()
                if host_val:
                    hosts_set.add(host_val)
                
            # Each sheet can define:
            # Which columns to check (column_filter_lookup)
            # Which patterns to include (filter)
            # Which patterns to exclude (filter_exclude)
            # Whether matching should be case-insensitive.

                for sheet_config in config.get("sheets", {}).values():
                    sheet_name = sheet_config.get("sheet_name")

                    """
                    If regex_flags = re.IGNORECASE, this means: case-insensitive regex matching
                    If regex_flags = 0, this means: no special flags, normal regex, case-sensitive.
                    """
                    regex_flags = re.IGNORECASE if sheet_config.get("case_insensitive", False) else 0


                    """
                    Reads a list of regex patterns from column_filter_lookup
                    Compiles each pattern using re.compile()
                    Stores the compiled regex objects into a new list
                    """
                    # Compiles all regexes for performance and cleaner logic.
                    compiled_col_filter_patterns = [re.compile(pat, regex_flags) for pat in sheet_config.get("column_filter_lookup", [])]
                    compiled_filter_patterns = [re.compile(pat, regex_flags) for pat in sheet_config.get("filter", [])]
                    compiled_filter_exclude_patterns = [re.compile(pat, regex_flags) for pat in sheet_config.get("filter_exclude", [])]

                    # Helper function: returns True if any pattern in the list matches the text
                    def matches_any(patterns, text):
                        return any(pattern.search(text) for pattern in patterns)

                    # For each column in the row that matches the “column_filter_lookup” patterns:
                    # If the value matches at least one “filter” pattern
                    # AND doesn’t match any “filter_exclude” pattern
                    # → Then include this row under that sheet.

                    if any(
                        matches_any(compiled_filter_patterns, value) and not matches_any(compiled_filter_exclude_patterns, value)
                        for col_name, value in row.items() if matches_any(compiled_col_filter_patterns, col_name)
                    ):
                        sheets[sheet_name].append(row)
        
    except Exception as e:
        if logger:
            logger.error(f"Error reading CSV file {csv_filename}: {e}") # Logs any file read or parse errors.
        return

    # # --- Step 2. Create workbook and Hosts sheet ---
    wb = Workbook()
    default_sheet = wb.active
    wb.remove(default_sheet)

    # Go to config to find the key "hosts". If existed, print the subdictionary within the hosts key, otherwise print {}. WIthin the subdictionary, find the key "sheet_name" and get the value.
    # Otherwise the default value is "Hosts".  
    hosts_sheet = wb.create_sheet(config.get("hosts", {}).get("sheet_name", "Hosts")) #hosts_sheet = Hosts (Excel Sheet name is called "Hosts")
    hosts_header = config.get("hosts", {}).get("headers", ["Hostname", "IP", "OS"]) #hosts_header= ["Hostname", "IP", "OS"] (Headers for the Excel Sheet "Hosts")
    hosts_sheet.append(hosts_header) #Append the headers onto  the Hosts sheet
    for host in sorted(hosts_set):
        if IP_REGEX.match(host):
            row = config.get("hosts", {}).get("ip_match", ["", 1, ""])[:]
        else:
            row = config.get("hosts", {}).get("not_ip_match", [1, "", ""])[:]
            
        for i, val in enumerate(row):
            if val == 1:
                row[i] = host

        hosts_sheet.append(row)

    create_table_and_style(hosts_sheet, "Hosts", config.get("table", {})) 
    hide_and_autowidth_columns(hosts_sheet, config.get("hosts", {}).get("visible_columns", []), [])

    for sheet_config in config.get("sheets", {}).values():
        sheet_name = sheet_config.get("sheet_name")
        sheet = wb.create_sheet(sheet_name)
            
        write_csv_sheet(sheet, sheets[sheet_name], csv_header, config.get("sheet_options", {}), sheet_config.get("extract_config", {}))

        create_table_and_style(sheet, sheet_name, config.get("table", {}))
        add_lookup_formulas(sheet, hosts_sheet, config.get("sheet_options", {}))
        add_status_validation(sheet, config.get("status", {}))
        add_conditional_formatting(sheet, config.get("status", {}))
        hide_and_autowidth_columns(sheet, sheet_config.get("visible_columns", []), sheet_config.get("auto_width_columns", []))
        add_risk_font_formatting(sheet, sheet_config)

        # Add category dropdowns
        if sheet_name == "Compliance":
            add_validation(sheet, [
                "Missing OS or Software Patch",
                "Inadequate Hardening",
                "Unauthorised Network Shared Drive or Folder",
                "Approved ACMs not Implemented"
            ], "Category")
        elif sheet_name == "Vulnerabilities":
            add_validation(sheet, [
                "End-of-Life OS or software",
                "Software or Firmware Vulnerabilities"
            ], "Category")
        elif sheet_name == "Users":
            add_validation(sheet, [
                "Excessive Privileged Account"
            ], "Category", "Excessive Privileged Account")
        elif sheet_name == "Open Ports":
            add_validation(sheet, [
                "Unauthorised Open Port or Service or Devices"
            ], "Category", "Unauthorised Open Port or Service or Devices")
        elif sheet_name == "Installed Software":
            add_validation(sheet, [
                "Unauthorised Software or File",
            ], "Category", "Unauthorised Software or File")

    create_summary_sheet(wb)
    

    return wb

    # try:
    #     wb.save(excel_filename)
    #     if logger:
    #         logger.info(f"Excel file created successfully at: {excel_filename}")
    # except Exception as e:
    #     if logger:
    #         logger.error(f"Error saving Excel file {excel_filename}: {e}")



# The blueprint used by nessus_convert() - All the defualt settings of how the Excel report should look and behave

def generate_default_config():
    return  {
    
    # Defines what counts as an IP address (so hosts can be identified properly).
    "ip_regex": r"^((25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d|[Xx]{1,3})\.){3}(25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d|[Xx]{1,3})$",
    
    #Enables duplicate row removal from the CSV.
    "remove_duplicates": True,

    # Excel Table Styling
    "table": {
      "table_style": "TableStyleMedium9",
      "show_first_column": False,
      "show_last_column": False,
      "show_row_stripes": False,
      "show_column_stripes": False,
      "header_fill": "A5A5A5",
      "header_fill_type": "solid",
      "header_font_color": "000000",
      "cell_fill": "ffffff",
      "cell_fill_type": "solid",
      "cell_border": "thin",
      "cell_font_color": "000000"
    },

    # Status Formatting
    "status": {
      "status_map": {
        "-": "ffffff",
        "Open": "FFC7CE",
        "Follow up": "FFEB9C",
        "Closed": "82F073",
        "Declared": "8DB5F0"
      },
      "status_fill_type": "solid"
    },

    # Hosts Sheet Configuration
    "hosts": {
      "sheet_name": "Hosts",
      "table_name": "Hosts",
      "headers": ["Hostname", "IP", "OS"],
      "visible_columns": ["Hostname", "IP", "OS"],
      "ip_match": ["", 1, ""],  # If the value is an IP → put it in the IP column.
      "not_ip_match": [1, "", ""] # If not → treat it as a Hostname.
    },

    #  This defines the extra columns that will be added to each of the excel sheet stated below (besides CSV columns):
    "sheet_options": {
      "host_column_name": "Host",

    #   Add columns to the right after the "Risk" column
      "insert_mapping_columns_after": "Risk",

    # Add the following columns after the "Risk" column
      "mapping_columns": ["Hostname_original", "Hostname", "IP_original", "IP", "OS_original", "OS"], 

    # If the value is an IP --> put it in the IP_original column 
      "ip_match": ["", "", 1, "", "", ""],

    #If the value is not an IP --> put it in the Hostname_original column
      "not_ip_match": [1, "", "", "", "", ""],

    # The excel formula below makes use of the values within the Hostname_original, IP_original, and OS_original column to obtain the values
    # within the Hostname, IP, and OS column
      "mapping_columns_formula": {
        "Hostname": "=IF(ISBLANK({Hostname_original_cell}), IF(ISBLANK(INDEX({hosts_table_name}!$A$2:$A${host_rows}, MATCH({IP_original_cell}, {hosts_table_name}!$B$2:$B${host_rows}, 0))), \"\", INDEX({hosts_table_name}!$A$2:$A${host_rows}, MATCH({IP_original_cell}, {hosts_table_name}!$B$2:$B${host_rows}, 0))), {Hostname_original_cell})",
        "IP": "=IF(ISBLANK({IP_original_cell}), IF(ISBLANK(INDEX({hosts_table_name}!$B$2:$B${host_rows}, MATCH({Hostname_original_cell}, {hosts_table_name}!$A$2:$A${host_rows}, 0))), \"\", INDEX({hosts_table_name}!$B$2:$B${host_rows}, MATCH({Hostname_original_cell}, {hosts_table_name}!$A$2:$A${host_rows}, 0))), {IP_original_cell})",
        "OS": "=IF(ISBLANK({OS_original_cell}), IF(ISBLANK(INDEX({hosts_table_name}!$C$2:$C${host_rows}, MATCH({ip_cell}, {hosts_table_name}!$B$2:$B${host_rows}, 0))), \"\", INDEX({hosts_table_name}!$C$2:$C${host_rows}, MATCH({ip_cell}, {hosts_table_name}!$B$2:$B${host_rows}, 0))), {OS_original_cell})"
      },

    # The additional columns added after the OS column with the default value shown
      "additional_columns": {"Status": "Open","Category": "", "Remarks": "", "Remediation Plan": "", "Estimated date of completion": ""},

      "headers_to_remove": ["Host"]
    },

    # Config for each excel sheet
    "sheets": {
        # Vulnerabilties Sheet 
      "vulnerabilities":{
        "sheet_name": "Vulnerabilities",
        "case_insensitive": True,

        # Filters rows where Risk column matches these keywords below
        "filter": ["^None$", "^Low$", "^Medium$", "^High$", "^Critical$"],
        "column_filter_lookup": ["^Risk$"],
        "filter_exclude": [],

        # Display only these columns within the Vulnerabilities Sheet
        
        "visible_columns": ["Risk", "Hostname", "IP", "OS", "Name", "Synopsis", "Description", "Solution", "See Also", "Plugin Output", "Status", "Remarks", "Category", "Remediation Plan", "Estimated date of completion"],
        "auto_width_columns": [],

        # Applies text coloring for the different risk levels filtered within the "Risk" column
        "text_format_column": "Risk",
        "text_format": {
          "Low": "0000FF",
          "Medium": "A0522D",
          "High": "FF0000",
          "Critical": "8B0000"
        }
      },

        # Compliance Sheet
      "compliance":{
        "sheet_name": "Compliance",
        "case_insensitive": True,

        
        # Filters rows where Risk column matches these keywords below
        "filter": ["^WARNING$", "^FAILED$"],
        "column_filter_lookup": ["^Risk$"],
        "filter_exclude": [],

        # Display only these columns within the Compliance Sheet
      
        "visible_columns": ["Risk", "Hostname", "IP", "OS", "Name", "Synopsis", "Description", "Solution", "See Also", "Plugin Output", "Status", "Remarks", "Category", "Remediation Plan", "Estimated date of completion"],
        "auto_width_columns": [],

        # Applies text coloring for the different risk levels filtered within the "Risk" column
        "text_format_column": "Risk",
        "text_format": {
          "WARNING": "A0522D",
          "FAILED": "FF0000"
        }
      },


     #  Open Ports Sheet
      "open_ports":{
        "sheet_name": "Open Ports",
        "case_insensitive": True,

        # Filter rows where Name column matches these keywords below
        "filter": ["Netstat Portscanner \(SSH\)", "Netstat Portscanner \(WMI\)"],
        "column_filter_lookup": ["^Name$"],
        "filter_exclude": [],

         # Display only these columns within the Open Ports Sheet
 
        "visible_columns": ["Hostname", "IP", "OS", "Protocol", "Port", "Status", "Remarks", "Category", "Remediation Plan", "Estimated date of completion"],
        "auto_width_columns": []
      },

      # Users Sheet
      "users":{
        "sheet_name": "Users",
        "case_insensitive": True,

         # Filter rows where Name column matches these keywords below
        "filter": ["^Linux User List Enumeration$", "^Enumerate Users via WMI$"],
        "column_filter_lookup": ["^Name$"],
        "filter_exclude": [],

         # Display only these columns within the Users Sheet
   
        "visible_columns": ["Hostname", "IP", "OS", "User", "Status", "Remarks", "Category", "Remediation Plan", "Estimated date of completion"],
        "auto_width_columns": [],

        "extract_config": {
        
          # Makes all regex lookups and matches case-insensitive.
          "case_insensitive": True,
          
          #Tells the script which column(s) to look at to decide what kind of extraction rule to apply.
        # “Look inside the Name column — that’s where you’ll find the plugin title
        # like Linux User List Enumeration or Enumerate Users via WMI.”
          "lookup_columns": ["^Name$"], 

          #Once you know which rule to apply, extract data from the Plugin Output column.
          "extract_columns": ["^Plugin Output$"],
          
          # Defines the destination column to store the parsed results.
          "extract_column_name": "User",

          "linux": {
              "lookup_values": ["^Linux User List Enumeration$"],
              "extraction": {
                  # #treats each match as a separate entry,
                  #so each user becomes a new row under the “User” sheet, preserving Hostname/IP context.

                  "regex": ["^User\s*:\s*(.+)$"], 
                  "exclude": []
              }
          },

          "windows": {
              "lookup_values": ["^Enumerate Users via WMI$"],
              "extraction": {
                  
                  # #treats each match as a separate entry,
                  #so each user becomes a new row under the “User” sheet, preserving Hostname/IP context.

                  "regex": ["^Name\s*:\s*(.+)$"], 
                  "exclude": ["no\.?\s*of\s*users"]
              }
          }

        }

      },

        # Installed Software Sheet
      "installed_software":{
        "sheet_name": "Installed Software",
        "case_insensitive": True,

        # Include only rows where the Name column contains “software enumeration”.
        "filter": ["software enumeration"],
        "column_filter_lookup": ["^Name$"],

        # From those rows, exclude any that also mention “identification”, “startup”, or “start-up”.
        "filter_exclude": ["identification", "startup", "start-up"],
        
        "visible_columns": ["Hostname", "IP", "OS", "Installed Program", "Status", "Remarks", "Category", "Remediation Plan", "Estimated date of completion"],
     
     
        "auto_width_columns": [],

        "extract_config": {
          "case_insensitive": True,

        # Look up the Name column  
          "lookup_columns": ["^Name$"],


          "extract_columns": ["^Plugin Output$"], # Extract data from the Plugin Output column after identifying the condition
          
          "extract_column_name": "Installed Program", # Saved the extracted data to the Installed Program column


        # For Linux hosts, extract every line from the Plugin Output except:
        # --> Lines that just say “list of packages,” and
        # --> Lines made of dashes.

          "linux": {
            #   If the value in the name column contain the word "ssh""
              "lookup_values": ["ssh"],
              "extraction": {
                  "regex": [".*"], # Match the whole line, whatever it is
                  "exclude": ["list of packages", "^-+"] # skip lines containing the phrase "list of packages" and lines made only of dashes
              }
          },

        #   For Windows hosts, only extract lines mentioning “installed on,”
        #   and ignore generic text like “the following software.”

          "windows": {
              # If the value in the name column contain the phrase "microsoft windows installed software enumeration"
              "lookup_values": ["microsoft windows installed software enumeration"],
              "extraction": {
                #   Match only lines that contain the phrase “installed on”, anywhere in the line.
                  "regex": [".*installed on.*"],

                #   Skip lines containing that phrase "the following software"
                  "exclude": ["the following software"] 
              }
          }

        }
      }
    }
  }