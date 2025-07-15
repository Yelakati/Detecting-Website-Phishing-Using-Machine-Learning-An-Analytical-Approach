"""
Helper script to save a trained ELM model for use in the web application
"""

import os
import sys
import h5py
import pickle
import numpy as np

class ExtremeLearningMachine:
    """Simple ELM implementation for model saving purposes"""
    def __init__(self, input_size, hidden_size, output_size, activation='sigmoid'):
        self.input_size = input_size
        self.hidden_size = hidden_size
        self.output_size = output_size
        self.activation_name = activation
        
        # Activation function
        if activation == 'sigmoid':
            self.activation = self.sigmoid
        elif activation == 'relu':
            self.activation = self.relu
        elif activation == 'tanh':
            self.activation = self.tanh
        else:
            raise ValueError(f"Activation function {activation} not supported")
            
        # Initialize weights (will be set from the trained model)
        self.input_weights = None
        self.bias = None
        self.output_weights = None
    
    def sigmoid(self, x):
        return 1 / (1 + np.exp(-x))
    
    def relu(self, x):
        return np.maximum(0, x)
    
    def tanh(self, x):
        return np.tanh(x)
    
    def predict(self, X):
        # Forward pass
        H = self.calculate_hidden_layer_output(X)
        output = np.dot(H, self.output_weights)
        
        # Convert to class labels
        if self.output_size > 1:
            return np.argmax(output, axis=1)
        else:
            return (output > 0.5).astype(int).flatten()
    
    def calculate_hidden_layer_output(self, X):
        hidden_layer_input = np.dot(X, self.input_weights) + self.bias
        hidden_layer_output = self.activation(hidden_layer_input)
        return hidden_layer_output

def save_elm_model_to_h5(model, file_path):
    """Save the ELM model parameters to an h5 file."""
    try:
        with h5py.File(file_path, 'w') as hf:
            # Save model configuration
            hf.attrs['input_size'] = model.input_size
            hf.attrs['hidden_size'] = model.hidden_size
            hf.attrs['output_size'] = model.output_size
            
            # Activation function type
            hf.attrs['activation'] = model.activation_name
            
            # Save weights and bias
            hf.create_dataset('input_weights', data=model.input_weights)
            hf.create_dataset('bias', data=model.bias)
            hf.create_dataset('output_weights', data=model.output_weights)
            
        print(f"Model saved to {file_path}")
        return True
    except Exception as e:
        print(f"Error saving model: {e}")
        return False

def main():
    """Manual helper function to create a model from notebook variables"""
    print("=" * 50)
    print("ELM Model Saver for Web Application")
    print("=" * 50)
    print("\nThis script helps save your trained ELM model for use in the web application.")
    print("You should run this after training your model in the notebook.")
    
    # Create directories
    os.makedirs(os.path.join('static', 'models'), exist_ok=True)
    
    # Get model parameters
    try:
        input_size = int(input("Enter input_size (number of features, e.g., 48): "))
        hidden_size = int(input("Enter hidden_size (from best_params, e.g., 500): "))
        output_size = int(input("Enter output_size (usually 1 for binary classification): "))
        activation = input("Enter activation function (sigmoid, relu, tanh): ")
        
        # Create model object
        model = ExtremeLearningMachine(
            input_size=input_size,
            hidden_size=hidden_size,
            output_size=output_size,
            activation=activation
        )
        
        # Get weights and biases
        print("\nNow you need to save the model weights from your notebook to numpy files.")
        print("In your notebook, add and run these lines after training:")
        print("  np.save('input_weights.npy', final_elm.input_weights)")
        print("  np.save('bias.npy', final_elm.bias)")
        print("  np.save('output_weights.npy', final_elm.output_weights)")
        print("  pickle.dump(scaler, open('scaler.pkl', 'wb'))")
        
        input("\nPress Enter when you've created these files...")
        
        # Load the weights
        try:
            model.input_weights = np.load('input_weights.npy')
            model.bias = np.load('bias.npy')
            model.output_weights = np.load('output_weights.npy')
            
            # Check if scaler exists
            if not os.path.exists('scaler.pkl'):
                print("Warning: scaler.pkl not found!")
            
            # Save model
            model_path = os.path.join('static', 'models', 'phishing_elm_model.h5')
            scaler_path = os.path.join('static', 'models', 'scaler.pkl')
            
            if save_elm_model_to_h5(model, model_path):
                # Copy scaler if it exists
                if os.path.exists('scaler.pkl'):
                    import shutil
                    shutil.copy('scaler.pkl', scaler_path)
                    print(f"Scaler saved to {scaler_path}")
                    
                print("\nSuccess! Your model is now ready for the web application.")
                print("You can run the Flask app with: python app.py")
            else:
                print("\nFailed to save the model.")
                
        except FileNotFoundError as e:
            print(f"Error: {e}")
            print("Make sure you've created the weight files from your notebook first.")
        except Exception as e:
            print(f"Unexpected error: {e}")
            
    except ValueError:
        print("Invalid input. Please enter numeric values for sizes.")
    except KeyboardInterrupt:
        print("\nOperation cancelled by user.")
    
if __name__ == "__main__":
    main() 