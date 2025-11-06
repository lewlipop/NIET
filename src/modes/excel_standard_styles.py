#The standardise styles used for all excel sheets.

from openpyxl.styles import Alignment, Font
from openpyxl.styles.borders import Border, Side

# Standard font for headers (Bold Black)
HEADER_FONT = Font(bold=True, color="000000")

# Center alignment used for headers and selected cells
CENTER_ALIGN = Alignment(horizontal="center", vertical="center")

# Top alignment used for cells within headers
TOP_ALIGN = Alignment(vertical='top', wrap_text=True)

# Full Border Design for excel table
ALL_BORDERS_STYLES = Border(
    left=Side(style='thin'),
    right=Side(style='thin'),
    top=Side(style='thin'),
    bottom=Side(style='thin')
)