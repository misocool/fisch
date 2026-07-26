
from google import genai

gemini_client = genai.Client()

def generate_analysis(profile):

    prompt = """
        {profile}
    """

    interaction = gemini_client.interactions.create(
        model="gemini-3.5-flash",
        input=prompt
    )

    return interaction.text