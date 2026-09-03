from flask import Flask, render_template

app = Flask(__name__)

MEMBERS = [
    {
        "member_id": f"DEMO-{1000 + number}",
        "name": name,
        "profession": profession,
        "city": city,
        "email": email,
        "phone": f"+91 90000 {1000 + number:05d}",
    }
    for number, (name, profession, city, email) in enumerate(
        [
            ("Aarav Mehta", "Security Analyst", "Pune", "aarav.mehta@example.test"),
            ("Diya Sharma", "Data Engineer", "Bengaluru", "diya.sharma@example.test"),
            ("Kabir Rao", "Product Designer", "Hyderabad", "kabir.rao@example.test"),
            ("Meera Nair", "Cloud Architect", "Kochi", "meera.nair@example.test"),
            ("Ishaan Kapoor", "Legal Consultant", "New Delhi", "ishaan.kapoor@example.test"),
            ("Ananya Iyer", "Research Scientist", "Chennai", "ananya.iyer@example.test"),
            ("Rohan Desai", "Financial Advisor", "Mumbai", "rohan.desai@example.test"),
            ("Sana Khan", "UX Researcher", "Jaipur", "sana.khan@example.test"),
            ("Vikram Singh", "Operations Manager", "Chandigarh", "vikram.singh@example.test"),
            ("Tara Bose", "Software Developer", "Kolkata", "tara.bose@example.test"),
        ],
        start=1,
    )
]


@app.get("/")
def member_directory():
    return render_template("index.html", members=MEMBERS)


@app.get("/admin")
def admin_dashboard():
    return render_template("admin.html")


if __name__ == "__main__":
    app.run(debug=True)
