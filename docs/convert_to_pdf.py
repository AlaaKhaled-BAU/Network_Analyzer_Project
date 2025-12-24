from markdown_pdf import MarkdownPdf, Section
import re

input_path = r"C:\Users\DELL\Desktop\Network_Analyzer_Project\docs\DASHBOARD_DATA_FLOW_GUIDE.md"
output_path = input_path.replace(".md", ".pdf")

with open(input_path, "r", encoding="utf-8") as f:
    content = f.read()

# Remove box-drawing characters that cause issues
content = content.replace("┌", "+").replace("┐", "+")
content = content.replace("└", "+").replace("┘", "+")
content = content.replace("├", "+").replace("┤", "+")
content = content.replace("─", "-").replace("│", "|")
content = content.replace("▼", "v").replace("▶", ">")

# Remove the Table of Contents section (causes link errors)
content = re.sub(r'## Table of Contents.*?(?=\n## )', '', content, flags=re.DOTALL)

# Remove all internal anchor links like [text](#anchor)
content = re.sub(r'\[([^\]]+)\]\(#[^)]+\)', r'\1', content)

# Create PDF without TOC
pdf = MarkdownPdf(toc_level=0)  # Disable TOC
pdf.add_section(Section(content, toc=False))
pdf.save(output_path)

print(f"✅ PDF created at: {output_path}")
