import streamlit as st
import preprocessor, helper
import matplotlib.pyplot as plt
import seaborn as sns
import json
import os
import re
import warnings
import bcrypt

warnings.filterwarnings("ignore")

st.set_page_config(page_title="WhatsApp Chat Analyzer", layout="wide")

USERS_DB_FILE = "users_db.json"


# ------------------ User Auth ------------------

def load_users():
    if os.path.exists(USERS_DB_FILE):
        with open(USERS_DB_FILE, "r") as f:
            return json.load(f)
    return {}

def save_users(users):
    with open(USERS_DB_FILE, "w") as f:
        json.dump(users, f, indent=4)

def is_strong_password(password):
    return (
        len(password) >= 8 and
        re.search(r"[A-Z]", password) and
        re.search(r"[a-z]", password) and
        re.search(r"[0-9]", password) and
        re.search(r"[!@#$%^&*()_+]", password)
    )

def signup_ui():
    st.subheader("🔐 Sign Up")

    with st.form("signup_form"):
        username = st.text_input("Choose a Username")
        password = st.text_input("Choose a Password", type="password")
        confirm_password = st.text_input("Confirm Password", type="password")
        st.caption("⚠️ Password must be at least 8 characters long and include uppercase, lowercase, number, and special symbol.")
        submitted = st.form_submit_button("Sign Up")

        if submitted:
            users = load_users()

            if not username or not password or not confirm_password:
                st.error("All fields are required.")
                return

            if username in users:
                st.error("🚫 Username already exists.")
                return

            if password != confirm_password:
                st.error("Passwords do not match.")
                return

            if not is_strong_password(password):
                st.error("Weak password. Please follow the required format.")
                return

            hashed_pw = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
            users[username] = hashed_pw
            save_users(users)
            st.success("✅ Account created successfully! Please log in.")

def login_ui():
    st.subheader("🔓 Login")

    username = st.text_input("Username")
    password = st.text_input("Password", type="password")

    if st.button("Login"):
        users = load_users()
        if username in users and bcrypt.checkpw(password.encode(), users[username].encode()):
            st.success("Login successful!")
            st.session_state["logged_in"] = True
            st.session_state["user"] = username
            st.rerun()
        else:
            st.error("Invalid username or password.")

def auth_ui():
    st.markdown("<h1 style='text-align: center; color: green;'>📱 WhatsApp Chat Analyzer</h1>", unsafe_allow_html=True)
    auth_choice = st.radio("Select Action", ["Login", "Sign Up"], horizontal=True)

    if auth_choice == "Login":
        login_ui()
    else:
        signup_ui()


# ------------------ WhatsApp Analyzer ------------------

def whatsapp_analyzer():
    st.markdown("<h2 style='text-align: center; color: #1DB954;'>📊 WhatsApp Chat Analyzer</h2>", unsafe_allow_html=True)

    st.sidebar.image("https://img.icons8.com/fluency/96/whatsapp.png", width=80)
    st.sidebar.header("📂 Upload WhatsApp Chat")
    uploaded_file = st.sidebar.file_uploader("Upload a .txt chat export", type=["txt"])

    if uploaded_file is not None:
        bytes_data = uploaded_file.getvalue()
        data = bytes_data.decode("utf-8")
        df = preprocessor.preprocess(data)

        user_list = df['user'].unique().tolist()
        user_list.sort()
        user_list.insert(0, "Overall")

        selected_user = st.sidebar.selectbox("👤 Analyze for", user_list)

        if st.sidebar.button("🚀 Start Analysis"):
            num_messages, words, num_media_messages, num_links = helper.fetch_stats(selected_user, df)

            st.markdown("### 📊 Key Chat Statistics")
            col1, col2, col3, col4 = st.columns(4)
            col1.metric("💬 Messages", num_messages)
            col2.metric("📝 Words", words)
            col3.metric("📸 Media", num_media_messages)
            col4.metric("🔗 Links", num_links)

            st.markdown("---")

            if selected_user == "Overall":
                st.markdown("### 👥 Most Active Participants")
                x, new_df = helper.most_busy_users(df)
                fig, ax = plt.subplots()
                ax.bar(x.index, x.values, color='#FF7F50')
                plt.xticks(rotation='vertical')
                st.pyplot(fig)
                st.dataframe(new_df.style.highlight_max(axis=0))

            st.markdown("### ☁️ Word Cloud")
            df_wc = helper.create_wordcloud(selected_user, df)
            fig, ax = plt.subplots()
            ax.imshow(df_wc)
            ax.axis("off")
            st.pyplot(fig)

            st.markdown("### 💬 Most Common Words")
            most_common_df = helper.most_common_words(selected_user, df)
            fig, ax = plt.subplots()
            ax.barh(most_common_df[0], most_common_df[1], color="#00BFFF")
            plt.xticks(rotation=45)
            st.pyplot(fig)

            st.markdown("### 📅 Monthly Timeline")
            timeline = helper.monthy_timeline(selected_user, df)
            fig, ax = plt.subplots()
            ax.plot(timeline['time'], timeline['message'], color='#28A745')
            plt.xticks(rotation='vertical')
            st.pyplot(fig)

            st.markdown("### 📆 Daily Activity")
            daily_timeline = helper.daily_timeline(selected_user, df)
            fig, ax = plt.subplots()
            ax.plot(daily_timeline['only_date'], daily_timeline['message'], color='#007BFF')
            plt.xticks(rotation='vertical')
            st.pyplot(fig)

            st.markdown("### 🗓️ Activity Patterns")
            col1, col2 = st.columns(2)

            with col1:
                st.markdown("**🔁 Weekday Activity**")
                busy_day = helper.week_activity_map(selected_user, df)
                fig, ax = plt.subplots()
                ax.bar(busy_day.index, busy_day.values, color="#9370DB")
                st.pyplot(fig)

            with col2:
                st.markdown("**📆 Monthly Activity**")
                busy_month = helper.month_activity_map(selected_user, df)
                fig, ax = plt.subplots()
                ax.bar(busy_month.index, busy_month.values, color="#F4A460")
                st.pyplot(fig)

            st.markdown("### 🔥 Weekly Heatmap")
            user_heatmap = helper.activity_heatmap(selected_user, df)
            fig, ax = plt.subplots(figsize=(10, 6))
            sns.heatmap(user_heatmap, ax=ax, cmap="YlOrBr", linewidths=0.3, linecolor='gray')
            st.pyplot(fig)


# ------------------ App Entry ------------------

def main():
    if "logged_in" not in st.session_state:
        st.session_state["logged_in"] = False

    if st.session_state["logged_in"]:
        whatsapp_analyzer()
    else:
        auth_ui()


if __name__ == "__main__":
    main()
