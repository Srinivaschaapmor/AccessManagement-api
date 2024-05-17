from common_utils.Config import Config
from openai import OpenAI
import os

os.environ["OPENAI_API_KEY"] = Config.openai_key
client = OpenAI()

def openai_classifier(question, message_content):
    completion = client.chat.completions.create(
    model="gpt-3.5-turbo",
    temperature = 0,
    messages=[
        {"role": "system", "content": message_content},
        {"role": "user", "content": question}])

    return completion.choices[0].message.content


if __name__ == '__main__':

    message_content = """
                      You are an expert sentence classifier who can classify if sentences fall within two types 1) requests_questions or 2) pdf_questions

                      Sentences of type requests_questions are as follows. If the questions asks quesries about status or request ids it belongs to type requests_questions
                      - What is the status of my last request?
                      - What's the current status of my most recent inquiry?
                      - Show me my last 5 approved request.
                      - Display my prior accepted inquiry.
                      - Show me my last 5 rejected requests
                      - Display my prior reject inquiry.
                      - Display my most recent 3 cancelled request.
                      - Present my latest cancelled inquiry.
                      - Can you retrieve the request that was Partially Approved earlier?
                      - Can you show me what I requested last that was Partially Approved?
                      - Present my latest pending inquiry.
                      - Can you retrieve the request that was pending earlier?
                      - Show me my previous unsubscribed request
                     - Pull up my last unsubscribed inquiry please.

                     Senetences of type pdf_questions are as follows. If the questions does not ask queries about status or request ids it belongs to type pdf_questions.
                      - What is sql
                      - how to install windows

                     Q: Show me last 10 rejected request
                     A: {"type":"requests_questions"}

                     Q: who is the president
                     A: {"status":"pdf_questions"}
                     """


    ans = openai_classifier("what are the steps to install windows? 1)downlaod windows 2) purchase license 3)check email for key 4)enter key when prompted ", message_content)
    print(ans)

