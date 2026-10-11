from flask import Flask, render_template

app = Flask(__name__)


@app.get("/")
def home():
    return render_template("index.html")


if __name__ == "__main__":
    # Local development only. Render uses the Gunicorn command in render.yaml.
    app.run(host="127.0.0.1", port=5000, debug=True)
