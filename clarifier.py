import google.generativeai as genai
from googletrans import Translator

# Initialize the translator
translator = Translator()

# Configure your Gemini API key
genai.configure(api_key="AIzaSyBIB5H6Ft7ar1XBMIdpMiPiwUMqXYgY2N0")  # Replace with your real API key

# Load the Gemini model
model = genai.GenerativeModel("gemini-1.5-flash")

# Function to call Gemini with a prompt
def call_gemini(prompt):
    try:
        response = model.generate_content(prompt)
        return response.text
    except Exception as e:
        print("Gemini API error:", e)
        return "Error contacting Gemini model."

# Function to clarify question if needed
def clarify_if_needed(question, chat_history=[]):
    detected_lang = translator.detect(question).lang
    translated_question = translator.translate(question, src=detected_lang, dest='en').text if detected_lang != 'en' else question

    # Build conversation context
    context = "You are a helpful legal assistant. Speak like a lawyer but keep it simple.\n\n"
    for entry in chat_history:
        role = entry['role']
        content = entry['content']
        context += f"{role.capitalize()}: {content}\n"
    context += f"User: {translated_question}\nAI:"

    # Get the main answer from Gemini
    answer = call_gemini(context)

    # Ask Gemini whether clarification is needed
    clarification_prompt = f"Given this answer:\n\"{answer}\"\nWas the user's question vague or ambiguous? If yes, suggest a clarifying question."
    clarification = call_gemini(clarification_prompt)

    # Translate response and clarification back to original language if needed
    if detected_lang != 'en':
        answer = translator.translate(answer, src='en', dest=detected_lang).text
        if "No" in clarification or "clear" in clarification.lower():
            return answer
        else:
            clarification_translated = translator.translate(clarification, src='en', dest=detected_lang).text
            return f"{answer}\n\n🤖 விளக்கம்: {clarification_translated.strip()}"
    else:
        if "No" in clarification or "clear" in clarification.lower():
            return answer
        else:
            return f"{answer}\n\n🤖 Clarification: {clarification.strip()}"
