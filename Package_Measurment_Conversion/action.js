// filepath: c:\Users\Lenovo\Desktop\Package_Measurement_conversion\Package_Measurment_Conversion\action.js
document.addEventListener('DOMContentLoaded', () => {
    const measurementInput = document.getElementById('measurementInput');
    const convertButton = document.getElementById('convertButton');
    const historyButton = document.getElementById('historyButton');
    const clearButton = document.getElementById('clearButton');
    const resultArea = document.getElementById('resultArea');
    
    convertButton.addEventListener('click', () => {
        const userInput = measurementInput.value.trim();
        if (!userInput) {
            resultArea.innerHTML = '<p class="error">Please enter a measurement input.</p>';
            return;
        }
        fetch(`http://localhost:8888/convert?convert-measurements=${encodeURIComponent(userInput)}`)
            .then(response => {
                if (!response.ok) {
                    throw new Error('Conversion failed. Please check your input or try again later.');
                }
                return response.json();
            })
            .then(data => {
                // Expected data example: { result: [2, 7, 7] } 
                resultArea.innerHTML = `<p>Converted Result: ${JSON.stringify(data.result)}</p>`;
            })
            .catch(error => {
                resultArea.innerHTML = `<p class="error">${error.message}</p>`;
            });
    });
    
    historyButton.addEventListener('click', () => {
        fetch('http://localhost:8888/secure-history')
            .then(response => {
                if (!response.ok) {
                    throw new Error('Failed to load history.');
                }
                return response.json();
            })
            .then(data => {
                let historyHtml = '<h2>Conversion History</h2>';
                data.secure_history.forEach(item => {
                    historyHtml += `<p>${item.input} -> ${JSON.stringify(item.result)} (${item.timestamp})</p>`;
                });
                resultArea.innerHTML = historyHtml;
            })
            .catch(error => {
                resultArea.innerHTML = `<p class="error">${error.message}</p>`;
            });
    });
    
    clearButton.addEventListener('click', () => {
        resultArea.innerHTML = '';
    });
});