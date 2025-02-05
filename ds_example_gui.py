import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext
from python_excel2json import parse_excel_to_json
import json
import os

class ExcelLoader:
    def __init__(self, path: str) -> None:
        self.path = path
        self.data = None

    def load(self) -> None:
        excel_sheets_format = {
            'start_row_sheet_parsing': 1,
            'start_column_sheet_parsing': 0,
            'sheet_formats': [
                {
                    'sheet_index': 1,
                    'column_names': [
                        {'name': 'Source server name', 'type': 'str'},
                        {'name': 'sourceAsg', 'type': 'str'},
                        {'name': 'Source IP', 'type': 'str'},
                        {'name': 'Destination server name', 'type': 'str'},
                        {'name': 'Destination IP', 'type': 'str'},
                        {'name': 'Destination port', 'type': 'str'},
                        {'name': 'Comment', 'type': 'str'},
                        {'name': 'Environment', 'type': 'str'},
                        {'name': 'destinationAsg', 'type': 'str'},
                        {'name': 'Az snet', 'type': 'str'}
                    ],
                    'is_ordered': True
                }
            ]
        }
        self.data = parse_excel_to_json(excel_sheets_format, self.path)

    def get_data(self) -> list:
        return self.data


class NSGRule:
    def __init__(self, priority: int, direction: str, source_asg: str, destination_asg: str, destination_port: str) -> None:
        self.priority = priority
        self.direction = direction
        self.source_asg = source_asg
        self.destination_asg = destination_asg
        self.destination_port = destination_port

    def to_dict(self) -> dict:
        return {
            'name': f'Allow-{self.direction}-{self.source_asg}-to-{self.destination_asg}-{self.destination_port}',
            'priority': self.priority,
            'direction': self.direction,
            'access': 'Allow',
            'protocol': 'Tcp',
            'sourcePortRanges': ['*'],
            'destinationPortRanges': [self.destination_port],
            'sourceApplicationSecurityGroups': [{'id': self.source_asg}],
            'destinationApplicationSecurityGroups': [{'id': self.destination_asg}]
        }


class NSGRuleProcessor:
    def __init__(self, data: list) -> None:
        self.data = data

    def process(self, output_dir: str) -> None:
        sheet_data = self.data[0].get("results")
        sorted_sheet_data = sorted(sheet_data, key=lambda x: x['Az snet'])

        counter = 0
        previous_subnet = ""

        for entry in sorted_sheet_data:
            subnet = entry.get("Az snet")
            if previous_subnet != subnet:
                counter = 0
            counter += 1
            previous_subnet = subnet

            inbound_nsg_rule = NSGRule(
                priority=1000 + counter,
                direction='Inbound',
                source_asg=entry.get("sourceAsg"),
                destination_asg=entry.get("destinationAsg"),
                destination_port=entry.get("Destination port")
            ).to_dict()

            outbound_nsg_rule = NSGRule(
                priority=1000 + counter,
                direction='Outbound',
                source_asg=entry.get("destinationAsg"),
                destination_asg=entry.get("sourceAsg"),
                destination_port=entry.get("Destination port")
            ).to_dict()

            self._write_to_file(subnet, 'inbound', inbound_nsg_rule, output_dir)
            self._write_to_file(subnet, 'outbound', outbound_nsg_rule, output_dir)

    @staticmethod
    def _write_to_file(subnet: str, direction: str, rule: dict, output_dir: str) -> None:
        filename = os.path.join(output_dir, f'{subnet}_{direction}.json')
        with open(filename, 'a') as file:
            file.write(json.dumps(rule, indent=4))
            file.write('\n')


class NSGRuleApp:
    def __init__(self, root):
        self.root = root
        self.root.title("NSG Rule Generator")
        self.root.geometry("600x400")

        self.file_path = None
        self.output_dir = None

        # File Selection
        self.file_label = tk.Label(root, text="Excel File:")
        self.file_label.grid(row=0, column=0, padx=10, pady=10)
        self.file_button = tk.Button(root, text="Browse", command=self.select_file)
        self.file_button.grid(row=0, column=1, padx=10, pady=10)

        # Output Directory Selection
        self.output_label = tk.Label(root, text="Output Directory:")
        self.output_label.grid(row=1, column=0, padx=10, pady=10)
        self.output_button = tk.Button(root, text="Browse", command=self.select_output_dir)
        self.output_button.grid(row=1, column=1, padx=10, pady=10)

        # Load Data Button
        self.load_button = tk.Button(root, text="Load Data", command=self.load_data, state=tk.DISABLED)
        self.load_button.grid(row=2, column=0, padx=10, pady=10)

        # Process Data Button
        self.process_button = tk.Button(root, text="Process Data", command=self.process_data, state=tk.DISABLED)
        self.process_button.grid(row=2, column=1, padx=10, pady=10)

        # Status Display
        self.status_text = scrolledtext.ScrolledText(root, width=70, height=15, state=tk.DISABLED)
        self.status_text.grid(row=3, column=0, columnspan=2, padx=10, pady=10)

    def select_file(self):
        self.file_path = filedialog.askopenfilename(filetypes=[("Excel files", "*.xls *.xlsx")])
        if self.file_path:
            self.update_status(f"Selected file: {self.file_path}")
            self.load_button.config(state=tk.NORMAL)

    def select_output_dir(self):
        self.output_dir = filedialog.askdirectory()
        if self.output_dir:
            self.update_status(f"Selected output directory: {self.output_dir}")
            self.process_button.config(state=tk.NORMAL)

    def load_data(self):
        try:
            self.loader = ExcelLoader(self.file_path)
            self.loader.load()
            self.update_status("Data loaded successfully.")
        except Exception as e:
            self.update_status(f"Error loading data: {str(e)}")

    def process_data(self):
        try:
            data = self.loader.get_data()
            processor = NSGRuleProcessor(data)
            processor.process(self.output_dir)
            self.update_status("Data processed successfully. JSON files created.")
        except Exception as e:
            self.update_status(f"Error processing data: {str(e)}")

    def update_status(self, message: str):
        self.status_text.config(state=tk.NORMAL)
        self.status_text.insert(tk.END, message + "\n")
        self.status_text.config(state=tk.DISABLED)
        self.status_text.yview(tk.END)


if __name__ == "__main__":
    root = tk.Tk()
    app = NSGRuleApp(root)
    root.mainloop()