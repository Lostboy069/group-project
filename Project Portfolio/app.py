from flask import Flask, render_template, request

app = Flask(__name__)


@app.route("/")
def index():
    return render_template("index.html", active_page="home")


@app.route("/about")
def about():
    return render_template("about.html", active_page="about")


@app.route("/contact", methods=["GET", "POST"])
def contact():
    submitted = False
    name = None
    if request.method == "POST":
        name = request.form.get("name")
        email = request.form.get("email")
        message = request.form.get("message")
        # Basic Flask example: in a real app you'd save this to a
        # database or send an email here.
        print(f"New contact submission: name={name}, email={email}, message={message}")
        submitted = True
    return render_template("contact.html", active_page="contact", submitted=submitted, name=name)


if __name__ == "__main__":
    app.run(debug=True)
