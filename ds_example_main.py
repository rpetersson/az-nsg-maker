from python_excel2json import parse_excel_to_json
import json

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

    def process(self) -> None:
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

            self._write_to_file(subnet, 'inbound', inbound_nsg_rule)
            self._write_to_file(subnet, 'outbound', outbound_nsg_rule)

    @staticmethod
    def _write_to_file(subnet: str, direction: str, rule: dict) -> None:
        filename = f'{subnet}_{direction}.json'
        with open(filename, 'a') as file:
            file.write(json.dumps(rule, indent=4))
            file.write('\n')


def main():
    loader = ExcelLoader('/Users/robban/Downloads/azmigratefiltered.xls')
    loader.load()
    data = loader.get_data()

    processor = NSGRuleProcessor(data)
    processor.process()


if __name__ == "__main__":
    main()
