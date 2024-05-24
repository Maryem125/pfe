from joblib import load
from fastapi import FastAPI
from pydantic import BaseModel
import numpy as np
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
# Chargement du modèle
model = load('/home/osboxes/Downloads/pfe-main/rfmodel1.h5')
app = FastAPI()

# Définition du modèle de données
class RequestData(BaseModel):
    len: int
    entropy: float
    ratio: float
 

   
def processed_data(data: RequestData) -> np.ndarray:
    """ Préparer les données pour la prédiction. """

    # Créer un tableau numpy avec toutes les données nécessaires
    features = np.array([data.len, data.entropy, data.ratio])
    return features.reshape(1, -1)  # Reshape pour correspondre à l'entrée du modèle


# Définition du point de terminaison
@app.post("/predict")  # URL: http://127.0.0.1:8000/predict:endpoint

async def predict(data: RequestData):
    processeddata = processed_data(data)
    print(processeddata)
    # Prédiction
    prediction = model.predict(processeddata)[0]
    if prediction == 0:
        return (False)
    elif prediction==1:
        return(True)
'''
def run_api():
    Fonction pour démarrer l'API FastAPI 
    #uvicorn.run(app, host="127.0.0.1", port=8000, log_level="info")
        
'''