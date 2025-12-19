import streamlit as st
import hashlib

# ------------------ Page Config ------------------

st.set_page_config(
    page_title="Hash Calculator & Comparator",
    page_icon="🔐",
    layout="centered"
)

# ------------------ Helper Function ------------------

def compute_hash(file_bytes, algorithm):
    h = hashlib.new(algorithm)
    h.update(file_bytes)
    return h.hexdigest()

# ------------------ UI ------------------

st.title("🔐 Hash Calculator & Verification Tool")
st.markdown(
    "For **Cyber Security**, **Digital Forensics**, and **File Integrity Verification**"
)

st.divider()

# ------------------ Hash Generation ------------------

st.subheader("📁 File Hash Generation")

uploaded_file = st.file_uploader(
    "Upload a file",
    type=None
)

algorithm = st.selectbox(
    "Select Hash Algorithm",
    [
        "md5",
        "sha1",
        "sha224",
        "sha256",
        "sha384",
        "sha512",
        "blake2b",
        "blake2s"
    ]
)

if uploaded_file:
    file_bytes = uploaded_file.read()

    if st.button("Generate Hash"):
        hash_value = compute_hash(file_bytes, algorithm)
        st.success(f"**{algorithm.upper()} Hash:**")
        st.code(hash_value)

st.divider()

# ------------------ Hash Comparison ------------------

st.subheader("🔍 Hash Comparison")

hash1 = st.text_input("Enter Hash 1")
hash2 = st.text_input("Enter Hash 2")

if st.button("Compare Hashes"):
    if not hash1 or not hash2:
        st.warning("Please enter both hashes.")
    elif hash1.strip().lower() == hash2.strip().lower():
        st.success("✅ HASH MATCH")
    else:
        st.error("❌ HASH MISMATCH")

st.divider()

# ------------------ Footer ------------------

st.caption(
    "Developed for academic, forensic & cybersecurity demonstrations"
)
