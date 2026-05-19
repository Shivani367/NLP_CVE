import json
import sys

def extract_notebook_code(notebook_path, output_py_path):
    try:
        with open(notebook_path, 'r', encoding='utf-8') as f:
            notebook = json.load(f)
        
        code_blocks = []
        for i, cell in enumerate(notebook.get('cells', [])):
            cell_type = cell.get('cell_type')
            source = cell.get('source', [])
            
            # Convert list of lines to a single string
            source_str = "".join(source) if isinstance(source, list) else source
            
            if cell_type == 'code':
                code_blocks.append(f"# ==========================================\n# CODE CELL {i+1}\n# ==========================================\n")
                # Comment out notebook-specific magics
                lines = source_str.splitlines()
                commented_lines = []
                for line in lines:
                    if line.strip().startswith('!') or line.strip().startswith('%'):
                        commented_lines.append(f"# {line}")
                    else:
                        commented_lines.append(line)
                code_blocks.append("\n".join(commented_lines) + "\n\n")
            elif cell_type == 'markdown':
                code_blocks.append(f'"""\n{source_str}\n"""\n\n')
                
        with open(output_py_path, 'w', encoding='utf-8') as f:
            f.write("".join(code_blocks))
            
        print(f"Successfully extracted code to {output_py_path}")
    except Exception as e:
        print(f"Error: {e}")

if __name__ == '__main__':
    extract_notebook_code(
        r"e:\AI_NLP\CVE_NLP_Trend_Analysis_with_prediction_(1).ipynb",
        r"e:\AI_NLP\extracted_notebook_code.py"
    )
