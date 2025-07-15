# Phishing Website Detection Web Application

This web application uses Extreme Learning Machine (ELM) to detect phishing websites. It provides a user-friendly interface for users to check if a website is legitimate or potentially a phishing site.

## Features

- URL-based phishing detection
- Advanced mode for manual feature input
- Real-time prediction with confidence score
- Responsive design for mobile and desktop
- Informative about page explaining the approach

## Prerequisites

- Python 3.8 or higher
- Flask and other dependencies listed in `requirements.txt`
- Trained ELM model in h5 format
- Trained scaler in pickle format

## Installation

1. Clone this repository:
   ```
   git clone https://github.com/yourusername/phishing-detection.git
   cd phishing-detection
   ```

2. Create a virtual environment and activate it:
   ```
   python -m venv venv
   
   # On Windows
   venv\Scripts\activate
   
   # On Unix or MacOS
   source venv/bin/activate
   ```

3. Install the required packages:
   ```
   pip install -r requirements.txt
   ```

4. Place your trained model files in the correct directory:
   - Move your `phishing_elm_model.h5` file to `static/models/`
   - Move your `scaler.pkl` file to `static/models/`
   
   If these files don't exist, you'll need to train the model first using the Jupyter notebook.

## Usage

1. Start the Flask application:
   ```
   python app.py
   ```

2. Open your browser and navigate to `http://127.0.0.1:5000`

3. Use the application by:
   - Entering a URL to check in the URL tab
   - OR manually entering website features in the Advanced tab

## Model Training

The model was trained using an Extreme Learning Machine on the Phishing_Legitimate_full.csv dataset. To train or retrain the model:

1. Run the Jupyter notebook `phishing_detection_elm.ipynb`
2. Add the following code at the end of the notebook to save the model and scaler:

```python
# Save the trained model to h5 format
import h5py
import pickle
import os

os.makedirs('static/models', exist_ok=True)

# Save the model
def save_elm_model_to_h5(model, file_path):
    with h5py.File(file_path, 'w') as hf:
        # Save model configuration
        hf.attrs['input_size'] = model.input_size
        hf.attrs['hidden_size'] = model.hidden_size
        hf.attrs['output_size'] = model.output_size
        
        # Activation function type
        if model.activation == model.sigmoid:
            hf.attrs['activation'] = 'sigmoid'
        elif model.activation == model.relu:
            hf.attrs['activation'] = 'relu'
        elif model.activation == model.tanh:
            hf.attrs['activation'] = 'tanh'
        
        # Save weights and bias
        hf.create_dataset('input_weights', data=model.input_weights)
        hf.create_dataset('bias', data=model.bias)
        hf.create_dataset('output_weights', data=model.output_weights)
        
    print(f"Model saved to {file_path}")

# Save the model and scaler
model_path = 'static/models/phishing_elm_model.h5'
scaler_path = 'static/models/scaler.pkl'

save_elm_model_to_h5(final_elm, model_path)

# Save the scaler
with open(scaler_path, 'wb') as f:
    pickle.dump(scaler, f)
```

## Deployment

For production deployment, consider using a WSGI server like gunicorn:

```
gunicorn app:app
```

You may also want to deploy the application on a cloud platform like Heroku, AWS, or Google Cloud Platform.

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Acknowledgments

- The ELM implementation is based on research by Huang et al.
- Dataset used for training: Phishing_Legitimate_full.csv
- Bootstrap for the frontend design 