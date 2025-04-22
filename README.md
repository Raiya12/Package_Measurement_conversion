# Package Measurement Conversion API

This project is a FastAPI application that provides an API for converting measurement input strings into a list of total values of measured inflows for each package.

## Prerequisites

- Python 3.7 or higher
- pip (Python package installer)

## Setup Instructions

1. **Clone the repository:**
   ```bash
   git clone <repository-url>
   cd Package_Measurement_conversion
   ```

2. **Create a virtual environment (optional but recommended):**
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows use `venv\Scripts\activate`
   ```

3. **Install the required dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

4. **Run the application:**
   ```bash
   uvicorn app.main:app --host 0.0.0.0 --port 8888 --reload
   ```

## API Usage

### Measurement Conversion Endpoint

- **Endpoint:** `/convert`
- **Method:** `GET`
- **Query Parameters:**
  - `input`: A string representing the measurement input to be converted.

#### Example Request

```bash
curl "http://localhost:8888/convert?convert-measurements=za_a_a_a_a_a_a_a_a_a_a_a_a_azaaa"
```

#### Example Response

```json
{
  "total_values": [value1, value2, ...]
}
```

## Contributing

Contributions are welcome! Please open an issue or submit a pull request for any improvements or bug fixes.

## License

This project is licensed under the MIT License. See the LICENSE file for details.

## for testing:
1) aa
2) abbcc
3) dz_a_aazzaaa 
4) a_
5) abcdabcdab
6) abcdabcdab_
7) zdaaaaaaaabaaaaaaaabaaaaaaaabbaa
8) zza_a_a_a_a_a_a_a_a_a_a_a_a_a_a_a_a_a_a_a_a_a_a_a_a_a_ 
9) za_a_a_a_a_a_a_a_a_a_a_a_a_azaaa

## results:
1) [1]
2) [2,6]
3) [28,53,1] 
4) [0]
5) [2,7,7]
6) [2,7,7,0]
7) [34]
8) [26] main
9) [40,1]