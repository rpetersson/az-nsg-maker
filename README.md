# az-nsg-maker

## Usage

To use `main.py`, run the following command:

```bash
python main.py --arg1 value1 --arg2 value2
```

Replace `--arg1` and `--arg2` with the appropriate arguments for your use case. For more details on the available arguments, you can run:

```bash
python main.py --help
```

### Running with Docker

To build the Docker container, run the following command in the project directory:

```bash
docker build -t nsg-maker .
```

To run the container and enter a command, use:

```bash
docker run -it nsg-maker bash
```

Once inside the container, you can run the script as follows:

```bash
python main.py -h
```

### Examples

1. **Basic Usage:**

   To process an Excel file named `input_2.xls` and store the output in the `output` directory, use the following command:

   ```bash
   python main.py input_2.xls output
   ```

2. **Custom Input and Output:**

   If you have a different input file and want to specify a different output directory:

   ```bash
   python main.py path/to/your/input_file.xls path/to/your/output_directory
   ```

3. **Help Command:**

   To see all available options and arguments:

   ```bash
   python main.py --help
   ```

### Purpose

This script is meant to be used with the Azure Migrate dependency Excel output to create azure NSGs. The Excel file should have the following columns:

| Source server name | sourceAsg     | Source IP      | Destination server name | Destination IP    | Destination port | Comment | Environment | destinationAsg     |
|--------------------|---------------|----------------|-------------------------|-------------------|------------------|---------|-------------|--------------------|
| server1            |               | 192.168.1.1    | server2                 | 192.168.2.1       | 8080             | HTTP    | PROD        |                    |
| server1            | sourceTestASg | 192.168.1.1    | server2                 | 192.168.2.1       | 8080             | HTTP    | PROD        | destinationTestASg |

Replace the example data with your actual data while maintaining the structure.

### How It Works

The program processes the Excel file and generates Network Security Group (NSG) rules based on the data. For each line in the Excel file, it creates two rules:

1. **Inbound Rule:** This rule allows traffic from the source to the destination.
2. **Outbound Rule:** This rule allows traffic from the destination back to the source.

The rules are generated based on the following columns in the Excel file:
- `sourceAsg`: Source Application Security Group
- `Source IP`: Source IP address
- `destinationAsg`: Destination Application Security Group
- `Destination IP`: Destination IP address
- `Destination port`: Destination port

The program handles empty cells by setting them to `None` and uses IP addresses if ASG values are not provided. The generated rules are saved as JSON files in the specified output directory.

### Custom Formats

If you have another format, define the columns in `schema.py` to match your Excel file structure.

### Example Output

Here is an example of how the generated output can look:

```json
[
    {
        "name": "Allow-Inbound-144.164.6.13-to-144.164.108.198-8082",
        "priority": 1000,
        "direction": "Inbound",
        "access": "Allow",
        "protocol": "Tcp",
        "sourcePortRanges": [
            "*"
        ],
        "destinationPortRanges": [
            "8082"
        ],
        "sourceAddressPrefixes": [
            "144.164.6.13"
        ],
        "destinationAddressPrefixes": [
            "144.164.108.198"
        ]
    }
]
```
