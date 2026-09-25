#!/usr/bin/env python3
"""Generate the NexVision ScamText Global dataset offline."""

from __future__ import annotations

import argparse
import gzip
import hashlib
import json
import os
import re
import shutil
import sys
import tempfile
from collections import Counter
from pathlib import Path


VERSION = "0.2.1"
RELEASE_DATE = "2026-09-23"
TAXONOMY_VERSION = "2026.09.23-3"
GENERATOR_VERSION = "deterministic-template-0.2.1"
LICENSE = "PolyForm-Noncommercial-1.0.0"
EXPECTED_CURATED_LANGUAGES = 18
DEFAULT_COUNTS = {
    "scam": 600_000,
    "benign": 350_000,
    "hard_negative": 250_000,
    "adversarial_scam": 200_000,
    "conversation_turn": 100_000,
}
ALLOWED_KINDS = frozenset(DEFAULT_COUNTS)
MANAGED_DATASET_NAMES = {
    "NexVision ScamText Global",
    "NexVision Global Scam Message Dataset",
}


# Five families in each of twelve macro groups. The taxonomy is intentionally
# multi-axis: family is not used as a substitute for action, objective or lure.
FAMILY_SPECS = [
    # Account and identity
    ("credential_phishing", "Credential phishing", "account verification", "credential theft", "financial services", "submit credentials"),
    ("account_suspension", "Account suspension", "account restriction", "account takeover", "online services", "verify account"),
    ("identity_kyc", "Identity or KYC theft", "identity verification", "identity theft", "regulated services", "upload identity document"),
    ("social_media_takeover", "Social-media takeover", "social account warning", "account takeover", "social media", "reset password"),
    ("sim_swap", "SIM-swap pretext", "mobile service change", "account takeover", "telecommunications", "disclose verification code"),
    # Authority and coercion
    ("government_impersonation", "Government impersonation", "official notice", "payment or identity theft", "government", "contact officer"),
    ("digital_arrest", "Digital-arrest scam", "remote investigation", "coercive payment theft", "law enforcement", "remain on call and transfer funds"),
    ("court_police_threat", "Court or police threat", "legal enforcement", "coercive payment theft", "justice", "pay alleged penalty"),
    ("tax_impersonation", "Tax-authority impersonation", "tax debt or refund", "payment or identity theft", "taxation", "pay or verify"),
    ("immigration_visa", "Immigration or visa scam", "immigration status", "payment or identity theft", "immigration", "pay fee or submit identity"),
    # Financial services
    ("bank_impersonation", "Bank impersonation", "bank security alert", "credential or payment theft", "banking", "verify transaction"),
    ("safe_account", "Safe-account transfer", "fund protection", "authorised payment diversion", "banking", "transfer to safe account"),
    ("loan_fee", "Advance-fee loan", "loan approval", "advance-fee theft", "credit", "pay release fee"),
    ("refund_rebate", "Refund or rebate scam", "refund entitlement", "credential or payment theft", "payments", "claim refund"),
    ("debt_collection", "False debt collection", "overdue debt", "coercive payment theft", "collections", "pay immediately"),
    # Investment and crypto
    ("investment", "Investment scam", "investment opportunity", "investment fraud", "investments", "deposit funds"),
    ("crypto_wallet", "Cryptocurrency-wallet scam", "wallet security or reward", "crypto-asset theft", "cryptocurrency", "connect wallet"),
    ("token_approval", "Token-approval scam", "token claim", "wallet-draining authorisation", "cryptocurrency", "approve token contract"),
    ("online_gambling", "Illegal gambling proposition", "betting reward", "deposit theft", "gambling", "deposit to unlock winnings"),
    ("influencer_endorsement", "Fake influencer endorsement", "celebrity opportunity", "investment or purchase fraud", "media", "join promoted scheme"),
    # Work and business
    ("job_task", "Job or task scam", "easy online work", "task-deposit theft", "employment", "pay to unlock task"),
    ("money_mule", "Money-mule recruitment", "payment-agent job", "movement of criminal proceeds", "employment", "receive and forward funds"),
    ("business_email_compromise", "Business payment diversion", "changed invoice details", "business payment theft", "business", "pay replacement account"),
    ("education_tuition", "Education-fee impersonation", "outstanding tuition", "payment theft", "education", "pay school fee"),
    ("scholarship", "Scholarship scam", "scholarship award", "advance-fee or identity theft", "education", "pay application fee"),
    # Commerce and delivery
    ("parcel_delivery", "Parcel-delivery phishing", "delivery failure", "payment or credential theft", "logistics", "pay redelivery fee"),
    ("customs_fee", "Customs-fee scam", "held parcel", "advance-fee theft", "customs", "pay clearance fee"),
    ("marketplace_buyer", "Marketplace buyer scam", "buyer or courier payment", "payment or credential theft", "marketplace", "use external payment link"),
    ("ecommerce_non_delivery", "E-commerce non-delivery", "online purchase", "purchase fraud", "retail", "pay seller directly"),
    ("fake_online_shop", "Fake online shop", "limited discount", "purchase and card theft", "retail", "buy through fake checkout"),
    # Personal relationships
    ("fake_friend", "Fake friend or new number", "changed phone number", "impersonation payment theft", "personal contact", "send urgent help"),
    ("family_emergency", "Family-emergency scam", "relative in crisis", "impersonation payment theft", "personal contact", "send emergency money"),
    ("romance", "Romance scam", "online relationship", "long-form financial exploitation", "dating", "send money"),
    ("wrong_number", "Wrong-number grooming", "accidental message", "relationship or investment grooming", "personal contact", "continue conversation"),
    ("dating_verification", "Dating-verification scam", "profile safety check", "card or identity theft", "dating", "pay verification charge"),
    # Rewards and advance fees
    ("prize_lottery", "Prize or lottery scam", "unexpected winnings", "advance-fee theft", "promotions", "pay claim fee"),
    ("advance_fee", "General advance-fee scam", "promised benefit", "advance-fee theft", "financial services", "pay upfront fee"),
    ("loyalty_points", "Loyalty-points phishing", "expiring rewards", "credential or payment theft", "retail", "redeem points"),
    ("survey_reward", "Survey-reward scam", "survey incentive", "credential or subscription fraud", "marketing", "complete reward form"),
    ("gift_card", "Gift-card payment scam", "urgent restricted payment", "irreversible payment theft", "retail", "send voucher codes"),
    # Technology and subscriptions
    ("tech_support", "Technical-support scam", "device compromise", "remote access or payment theft", "technology", "install remote software"),
    ("malware_delivery", "Malware-delivery message", "required application", "malware installation", "technology", "install application"),
    ("subscription_refund", "Subscription-refund scam", "unexpected renewal", "remote access or payment theft", "subscriptions", "call for refund"),
    ("qr_payment", "QR payment or credential scam", "QR verification", "payment or credential theft", "payments", "scan QR code"),
    ("deepfake_impersonation", "Deepfake or cloned-person impersonation", "executive or relative request", "payment diversion", "communications", "send confidential payment"),
    # Property, travel and services
    ("rental", "Rental-property scam", "property availability", "deposit or identity theft", "property", "pay viewing deposit"),
    ("travel_booking", "Travel-booking scam", "discount booking", "purchase or card theft", "travel", "pay reservation"),
    ("ticketing", "Event-ticket scam", "scarce ticket", "purchase fraud", "entertainment", "pay ticket seller"),
    ("pet_adoption", "Pet-adoption scam", "pet transport", "advance-fee theft", "animals", "pay transport fee"),
    ("legal_services", "Fake legal-services scam", "legal representation", "advance-fee or identity theft", "legal", "pay retainer"),
    # Health, charity and recovery
    ("healthcare_medical", "Healthcare or medical scam", "medical service or emergency", "payment or identity theft", "healthcare", "pay medical fee"),
    ("insurance", "Insurance scam", "claim or policy warning", "payment or identity theft", "insurance", "pay or verify policy"),
    ("charity", "Charity scam", "charitable appeal", "donation diversion", "charity", "send donation"),
    ("donation_disaster", "Disaster-donation scam", "urgent disaster relief", "donation diversion", "charity", "donate urgently"),
    ("recovery", "Fraud-recovery scam", "recovery of previous loss", "secondary victimisation", "recovery services", "pay recovery fee"),
    # Threat, billing and utilities
    ("blackmail_sextortion", "Blackmail or sextortion", "threatened exposure", "extortion", "personal communications", "pay to prevent publication"),
    ("utility_disconnection", "Utility-disconnection scam", "overdue utility bill", "urgent payment theft", "utilities", "pay to avoid disconnection"),
    ("toll_parking", "Toll, parking or traffic-fee scam", "unpaid road charge", "payment or credential theft", "transport", "pay alleged fine"),
    ("mobile_topup", "Mobile top-up scam", "mobile balance or reward", "payment theft", "telecommunications", "purchase top-up"),
    ("callback_premium", "Premium-rate callback scam", "missed urgent contact", "premium-call charging", "telecommunications", "call premium number"),
]


# Short seeds intentionally support reproducible research generation rather than
# claiming professional translation. Every pack remains not_reviewed in v0.2.1.
LANGUAGE_SEEDS = [
    ("en", "English", "Latn", "Urgent action required", "Verify your account", "Payment is required", "Send the security code", "Contact us now", "This is a legitimate service notice", "Do not click links or send money"),
    ("zh", "Chinese", "Hans", "请立即处理", "请验证您的账户", "需要付款", "发送验证码", "立即联系我们", "这是正常的服务通知", "不要点击链接或转账"),
    ("ms", "Malay", "Latn", "Tindakan segera diperlukan", "Sahkan akaun anda", "Bayaran diperlukan", "Hantar kod keselamatan", "Hubungi kami sekarang", "Ini notis perkhidmatan yang sah", "Jangan klik pautan atau hantar wang"),
    ("ta", "Tamil", "Taml", "உடனடி நடவடிக்கை தேவை", "உங்கள் கணக்கைச் சரிபார்க்கவும்", "பணம் செலுத்த வேண்டும்", "பாதுகாப்புக் குறியீட்டை அனுப்பவும்", "இப்போது தொடர்பு கொள்ளவும்", "இது சட்டபூர்வமான சேவை அறிவிப்பு", "இணைப்பைத் திறக்கவோ பணம் அனுப்பவோ வேண்டாம்"),
    ("id", "Indonesian", "Latn", "Tindakan segera diperlukan", "Verifikasi akun Anda", "Pembayaran diperlukan", "Kirim kode keamanan", "Hubungi kami sekarang", "Ini pemberitahuan layanan yang sah", "Jangan klik tautan atau kirim uang"),
    ("es", "Spanish", "Latn", "Se requiere acción urgente", "Verifica tu cuenta", "Se requiere un pago", "Envía el código de seguridad", "Contáctanos ahora", "Este es un aviso legítimo del servicio", "No pulses enlaces ni envíes dinero"),
    ("pt", "Portuguese", "Latn", "Ação urgente necessária", "Verifique sua conta", "É necessário pagamento", "Envie o código de segurança", "Entre em contato agora", "Este é um aviso legítimo do serviço", "Não clique em links nem envie dinheiro"),
    ("fr", "French", "Latn", "Action urgente requise", "Vérifiez votre compte", "Un paiement est requis", "Envoyez le code de sécurité", "Contactez-nous maintenant", "Ceci est un avis de service légitime", "Ne cliquez pas sur les liens et n'envoyez pas d'argent"),
    ("de", "German", "Latn", "Dringende Aktion erforderlich", "Bestätigen Sie Ihr Konto", "Eine Zahlung ist erforderlich", "Senden Sie den Sicherheitscode", "Kontaktieren Sie uns jetzt", "Dies ist eine legitime Service-Mitteilung", "Klicken Sie nicht auf Links und senden Sie kein Geld"),
    ("hi", "Hindi", "Deva", "तुरंत कार्रवाई आवश्यक है", "अपने खाते की पुष्टि करें", "भुगतान आवश्यक है", "सुरक्षा कोड भेजें", "अभी संपर्क करें", "यह एक वैध सेवा सूचना है", "लिंक पर क्लिक या पैसे न भेजें"),
    ("bn", "Bengali", "Beng", "জরুরি ব্যবস্থা প্রয়োজন", "আপনার অ্যাকাউন্ট যাচাই করুন", "পেমেন্ট প্রয়োজন", "নিরাপত্তা কোড পাঠান", "এখনই যোগাযোগ করুন", "এটি একটি বৈধ পরিষেবা বিজ্ঞপ্তি", "লিংকে ক্লিক বা টাকা পাঠাবেন না"),
    ("ur", "Urdu", "Arab", "فوری کارروائی ضروری ہے", "اپنے اکاؤنٹ کی تصدیق کریں", "ادائیگی ضروری ہے", "سیکیورٹی کوڈ بھیجیں", "ابھی رابطہ کریں", "یہ ایک جائز سروس اطلاع ہے", "لنک پر کلک یا رقم نہ بھیجیں"),
    ("ar", "Arabic", "Arab", "يلزم اتخاذ إجراء عاجل", "تحقق من حسابك", "الدفع مطلوب", "أرسل رمز الأمان", "اتصل بنا الآن", "هذا إشعار خدمة شرعي", "لا تضغط على الروابط ولا ترسل المال"),
    ("ja", "Japanese", "Jpan", "至急対応が必要です", "アカウントを確認してください", "支払いが必要です", "セキュリティコードを送信してください", "今すぐご連絡ください", "これは正規のサービス通知です", "リンクを開いたり送金したりしないでください"),
    ("ko", "Korean", "Kore", "긴급 조치가 필요합니다", "계정을 확인하세요", "결제가 필요합니다", "보안 코드를 보내세요", "지금 연락하세요", "정상적인 서비스 안내입니다", "링크를 누르거나 송금하지 마세요"),
    ("th", "Thai", "Thai", "ต้องดำเนินการด่วน", "ยืนยันบัญชีของคุณ", "ต้องชำระเงิน", "ส่งรหัสความปลอดภัย", "ติดต่อเราตอนนี้", "นี่คือประกาศบริการที่ถูกต้อง", "อย่ากดลิงก์หรือส่งเงิน"),
    ("vi", "Vietnamese", "Latn", "Cần hành động khẩn cấp", "Xác minh tài khoản của bạn", "Yêu cầu thanh toán", "Gửi mã bảo mật", "Liên hệ ngay", "Đây là thông báo dịch vụ hợp lệ", "Không nhấp liên kết hoặc gửi tiền"),
    ("tl", "Filipino", "Latn", "Kailangang kumilos agad", "I-verify ang iyong account", "Kailangan ang bayad", "Ipadala ang security code", "Makipag-ugnayan ngayon", "Lehitimong abiso ito ng serbisyo", "Huwag mag-click ng link o magpadala ng pera"),
    ("ru", "Russian", "Cyrl", "Требуется срочное действие", "Подтвердите свою учетную запись", "Требуется оплата", "Отправьте код безопасности", "Свяжитесь с нами сейчас", "Это законное служебное уведомление", "Не переходите по ссылкам и не отправляйте деньги"),
    ("it", "Italian", "Latn", "È richiesta un'azione urgente", "Verifica il tuo account", "È richiesto un pagamento", "Invia il codice di sicurezza", "Contattaci ora", "Questo è un avviso di servizio legittimo", "Non aprire link né inviare denaro"),
    ("nl", "Dutch", "Latn", "Dringende actie vereist", "Verifieer uw account", "Betaling is vereist", "Stuur de beveiligingscode", "Neem nu contact op", "Dit is een legitieme servicemelding", "Klik niet op links en stuur geen geld"),
    ("tr", "Turkish", "Latn", "Acil işlem gerekiyor", "Hesabınızı doğrulayın", "Ödeme gerekiyor", "Güvenlik kodunu gönderin", "Şimdi iletişime geçin", "Bu geçerli bir hizmet bildirimidir", "Bağlantıya tıklamayın veya para göndermeyin"),
    ("pl", "Polish", "Latn", "Wymagane pilne działanie", "Zweryfikuj swoje konto", "Wymagana jest płatność", "Wyślij kod bezpieczeństwa", "Skontaktuj się teraz", "To prawidłowe powiadomienie usługi", "Nie klikaj linków ani nie wysyłaj pieniędzy"),
    ("uk", "Ukrainian", "Cyrl", "Потрібна термінова дія", "Підтвердьте свій обліковий запис", "Потрібна оплата", "Надішліть код безпеки", "Зв'яжіться зараз", "Це законне службове повідомлення", "Не переходьте за посиланнями й не надсилайте гроші"),
    ("cs", "Czech", "Latn", "Je vyžadována naléhavá akce", "Ověřte svůj účet", "Je vyžadována platba", "Pošlete bezpečnostní kód", "Kontaktujte nás nyní", "Toto je legitimní oznámení služby", "Neklikejte na odkazy ani neposílejte peníze"),
    ("ro", "Romanian", "Latn", "Este necesară o acțiune urgentă", "Verificați contul", "Este necesară plata", "Trimiteți codul de securitate", "Contactați-ne acum", "Aceasta este o notificare legitimă", "Nu accesați linkuri și nu trimiteți bani"),
    ("el", "Greek", "Grek", "Απαιτείται επείγουσα ενέργεια", "Επαληθεύστε τον λογαριασμό σας", "Απαιτείται πληρωμή", "Στείλτε τον κωδικό ασφαλείας", "Επικοινωνήστε τώρα", "Αυτή είναι νόμιμη ειδοποίηση υπηρεσίας", "Μην ανοίγετε συνδέσμους ή στέλνετε χρήματα"),
    ("he", "Hebrew", "Hebr", "נדרשת פעולה דחופה", "אמתו את החשבון שלכם", "נדרש תשלום", "שלחו את קוד האבטחה", "צרו קשר עכשיו", "זוהי הודעת שירות חוקית", "אל תלחצו על קישורים ואל תשלחו כסף"),
    ("fa", "Persian", "Arab", "اقدام فوری لازم است", "حساب خود را تأیید کنید", "پرداخت لازم است", "کد امنیتی را ارسال کنید", "اکنون تماس بگیرید", "این یک اعلان معتبر خدمات است", "روی پیوند کلیک نکنید و پول نفرستید"),
    ("pa", "Punjabi", "Guru", "ਤੁਰੰਤ ਕਾਰਵਾਈ ਦੀ ਲੋੜ ਹੈ", "ਆਪਣੇ ਖਾਤੇ ਦੀ ਪੁਸ਼ਟੀ ਕਰੋ", "ਭੁਗਤਾਨ ਲੋੜੀਂਦਾ ਹੈ", "ਸੁਰੱਖਿਆ ਕੋਡ ਭੇਜੋ", "ਹੁਣ ਸੰਪਰਕ ਕਰੋ", "ਇਹ ਇੱਕ ਵੈਧ ਸੇਵਾ ਸੂਚਨਾ ਹੈ", "ਲਿੰਕ ਨਾ ਖੋਲ੍ਹੋ ਅਤੇ ਪੈਸੇ ਨਾ ਭੇਜੋ"),
    ("gu", "Gujarati", "Gujr", "તાત્કાલિક કાર્યવાહી જરૂરી છે", "તમારું ખાતું ચકાસો", "ચુકવણી જરૂરી છે", "સુરક્ષા કોડ મોકલો", "હમણાં સંપર્ક કરો", "આ માન્ય સેવા સૂચના છે", "લિંક પર ક્લિક કે પૈસા મોકલશો નહીં"),
    ("mr", "Marathi", "Deva", "तातडीची कारवाई आवश्यक आहे", "आपले खाते सत्यापित करा", "देयक आवश्यक आहे", "सुरक्षा कोड पाठवा", "आता संपर्क करा", "ही वैध सेवा सूचना आहे", "लिंक उघडू नका किंवा पैसे पाठवू नका"),
    ("te", "Telugu", "Telu", "తక్షణ చర్య అవసరం", "మీ ఖాతాను ధృవీకరించండి", "చెల్లింపు అవసరం", "భద్రతా కోడ్ పంపండి", "ఇప్పుడే సంప్రదించండి", "ఇది చెల్లుబాటు అయ్యే సేవా నోటీసు", "లింక్ నొక్కవద్దు లేదా డబ్బు పంపవద్దు"),
    ("kn", "Kannada", "Knda", "ತುರ್ತು ಕ್ರಮ ಅಗತ್ಯ", "ನಿಮ್ಮ ಖಾತೆಯನ್ನು ಪರಿಶೀಲಿಸಿ", "ಪಾವತಿ ಅಗತ್ಯ", "ಭದ್ರತಾ ಕೋಡ್ ಕಳುಹಿಸಿ", "ಈಗ ಸಂಪರ್ಕಿಸಿ", "ಇದು ಮಾನ್ಯ ಸೇವಾ ಸೂಚನೆ", "ಲಿಂಕ್ ತೆರೆಯಬೇಡಿ ಅಥವಾ ಹಣ ಕಳುಹಿಸಬೇಡಿ"),
    ("ml", "Malayalam", "Mlym", "അടിയന്തര നടപടി ആവശ്യമാണ്", "നിങ്ങളുടെ അക്കൗണ്ട് സ്ഥിരീകരിക്കുക", "പണമടയ്ക്കണം", "സുരക്ഷാ കോഡ് അയയ്ക്കുക", "ഇപ്പോൾ ബന്ധപ്പെടുക", "ഇത് സാധുവായ സേവന അറിയിപ്പാണ്", "ലിങ്ക് തുറക്കുകയോ പണം അയയ്ക്കുകയോ ചെയ്യരുത്"),
    ("my", "Burmese", "Mymr", "အရေးပေါ်လုပ်ဆောင်ရန်လိုသည်", "သင့်အကောင့်ကို အတည်ပြုပါ", "ငွေပေးချေရန်လိုသည်", "လုံခြုံရေးကုဒ်ကို ပို့ပါ", "ယခုဆက်သွယ်ပါ", "ဤသည် တရားဝင်ဝန်ဆောင်မှုအသိပေးချက်ဖြစ်သည်", "လင့်ခ်မနှိပ်ပါနှင့် ငွေမပို့ပါနှင့်"),
    ("km", "Khmer", "Khmr", "ត្រូវការសកម្មភាពបន្ទាន់", "ផ្ទៀងផ្ទាត់គណនីរបស់អ្នក", "ត្រូវការការទូទាត់", "ផ្ញើលេខកូដសុវត្ថិភាព", "ទាក់ទងឥឡូវនេះ", "នេះជាសេចក្តីជូនដំណឹងសេវាកម្មត្រឹមត្រូវ", "កុំចុចតំណ ឬផ្ញើប្រាក់"),
    ("lo", "Lao", "Laoo", "ຕ້ອງດຳເນີນການດ່ວນ", "ຢືນຢັນບັນຊີຂອງທ່ານ", "ຕ້ອງຊຳລະເງິນ", "ສົ່ງລະຫັດຄວາມປອດໄພ", "ຕິດຕໍ່ຕອນນີ້", "ນີ້ແມ່ນແຈ້ງການບໍລິການທີ່ຖືກຕ້ອງ", "ຢ່າກົດລິ້ງ ຫຼື ສົ່ງເງິນ"),
    ("si", "Sinhala", "Sinh", "හදිසි ක්‍රියාමාර්ගයක් අවශ්‍යයි", "ඔබගේ ගිණුම තහවුරු කරන්න", "ගෙවීමක් අවශ්‍යයි", "ආරක්ෂක කේතය යවන්න", "දැන් සම්බන්ධ වන්න", "මෙය වලංගු සේවා දැනුම්දීමකි", "සබැඳි විවෘත නොකරන්න හෝ මුදල් යවන්න එපා"),
    ("ne", "Nepali", "Deva", "तत्काल कारबाही आवश्यक छ", "आफ्नो खाता प्रमाणित गर्नुहोस्", "भुक्तानी आवश्यक छ", "सुरक्षा कोड पठाउनुहोस्", "अहिले सम्पर्क गर्नुहोस्", "यो वैध सेवा सूचना हो", "लिङ्क नखोल्नुहोस् वा पैसा नपठाउनुहोस्"),
    ("sw", "Swahili", "Latn", "Hatua ya haraka inahitajika", "Thibitisha akaunti yako", "Malipo yanahitajika", "Tuma msimbo wa usalama", "Wasiliana nasi sasa", "Hii ni taarifa halali ya huduma", "Usibofye viungo wala kutuma pesa"),
    ("ha", "Hausa", "Latn", "Ana buƙatar mataki na gaggawa", "Tabbatar da asusunka", "Ana buƙatar biyan kuɗi", "Aika lambar tsaro", "Tuntuɓe mu yanzu", "Wannan sanarwar sabis ce ta halal", "Kada ka danna mahaɗi ko aika kuɗi"),
    ("yo", "Yoruba", "Latn", "A nilo igbese pajawiri", "Jẹrisi akọọlẹ rẹ", "A nilo isanwo", "Fi koodu aabo ranṣẹ", "Kan si wa bayi", "Eyi jẹ akiyesi iṣẹ to tọ", "Ma tẹ ọna asopọ tabi fi owo ranṣẹ"),
    ("af", "Afrikaans", "Latn", "Dringende optrede word vereis", "Verifieer u rekening", "Betaling word vereis", "Stuur die sekuriteitskode", "Kontak ons nou", "Dit is 'n geldige dienskennisgewing", "Moenie skakels klik of geld stuur nie"),
    ("zu", "Zulu", "Latn", "Kudingeka isinyathelo esiphuthumayo", "Qinisekisa i-akhawunti yakho", "Kudingeka inkokhelo", "Thumela ikhodi yokuphepha", "Xhumana nathi manje", "Lesi isaziso sesevisi esisemthethweni", "Ungachofozi izixhumanisi noma uthumele imali"),
    ("sv", "Swedish", "Latn", "Brådskande åtgärd krävs", "Verifiera ditt konto", "Betalning krävs", "Skicka säkerhetskoden", "Kontakta oss nu", "Detta är ett legitimt servicemeddelande", "Klicka inte på länkar och skicka inga pengar"),
    ("no", "Norwegian", "Latn", "Haster: handling kreves", "Bekreft kontoen din", "Betaling kreves", "Send sikkerhetskoden", "Kontakt oss nå", "Dette er et legitimt tjenestevarsel", "Ikke klikk på lenker eller send penger"),
    ("da", "Danish", "Latn", "Der kræves hurtig handling", "Bekræft din konto", "Betaling er påkrævet", "Send sikkerhedskoden", "Kontakt os nu", "Dette er en legitim servicemeddelelse", "Klik ikke på links og send ikke penge"),
    ("fi", "Finnish", "Latn", "Kiireellisiä toimia tarvitaan", "Vahvista tilisi", "Maksu vaaditaan", "Lähetä turvakoodi", "Ota yhteyttä nyt", "Tämä on aito palveluilmoitus", "Älä napsauta linkkejä tai lähetä rahaa"),
    ("hu", "Hungarian", "Latn", "Sürgős intézkedés szükséges", "Ellenőrizze fiókját", "Fizetés szükséges", "Küldje el a biztonsági kódot", "Lépjen kapcsolatba most", "Ez egy jogos szolgáltatási értesítés", "Ne kattintson linkre és ne küldjön pénzt"),
]


CHANNELS = ("sms", "whatsapp", "telegram", "facebook", "instagram", "dm")
BRANDS = ("Northstar", "MetroPay", "ParcelOne", "CivicDesk", "CloudBox", "MarketHub", "SafeBank", "TravelPoint")
PAYMENTS = ("bank transfer", "cryptocurrency", "gift card", "payment link", "cash deposit", "mobile wallet")
LURES = ("urgency", "authority", "scarcity", "fear", "reward", "helpfulness", "secrecy", "social proof")
AMOUNTS = ("12.50", "29.90", "48.00", "75.00", "120.00", "250.00", "480.00", "950.00")
DEADLINES = ("10 minutes", "30 minutes", "one hour", "today", "before 18:00")
PATHS = ("verify", "secure", "claim", "review", "confirm", "support")
EVASIONS = ("leetspeak", "zero_width", "split_tokens", "percent_encoding", "mixed_script", "repeated_punctuation")
STYLE_CUES = (
    "Security notice", "Service message", "Account update", "Action reminder", "Important request",
    "Customer notice", "Transaction message", "Verification request", "Status update", "Support message",
    "Time-sensitive notice", "Review request", "Confirmation message", "Service alert", "Account message",
    "Required response", "Pending action", "Final service notice", "Immediate review", "Attention required",
)

ANCHOR_FILE = Path(__file__).resolve().parents[1] / "data" / "curated_anchor_packs.json"


def load_anchor_payload(path: Path) -> dict:
    if not path.is_file():
        raise FileNotFoundError(f"required anchor pack is missing: {path}")
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict) or not isinstance(payload.get("languages"), dict):
        raise ValueError("anchor pack must contain a languages object")
    if payload.get("licence") != LICENSE or payload.get("review_status") != "not_native_reviewed":
        raise ValueError("anchor pack licence or review status is invalid")
    if len(payload["languages"]) != EXPECTED_CURATED_LANGUAGES:
        raise ValueError(f"anchor pack must contain {EXPECTED_CURATED_LANGUAGES} languages")
    return payload


CURATED_ANCHOR_PAYLOAD = load_anchor_payload(ANCHOR_FILE)
CURATED_ANCHORS = CURATED_ANCHOR_PAYLOAD["languages"]
FAMILY_ANCHOR_KEYS = {
    "credential_phishing": "secret_request", "account_suspension": "secret_request",
    "identity_kyc": "secret_request", "social_media_takeover": "secret_request", "sim_swap": "secret_request",
    "government_impersonation": "urgency", "digital_arrest": "money_transfer",
    "court_police_threat": "urgency", "tax_impersonation": "money_transfer", "immigration_visa": "advance_fee",
    "bank_impersonation": "secret_request", "safe_account": "money_transfer", "loan_fee": "loan_offer",
    "refund_rebate": "secret_request", "debt_collection": "money_transfer",
    "investment": "investment", "crypto_wallet": "investment", "token_approval": "investment",
    "online_gambling": "guaranteed_return", "influencer_endorsement": "investment",
    "job_task": "job_offer", "money_mule": "job_offer", "business_email_compromise": "money_transfer",
    "education_tuition": "money_transfer", "scholarship": "advance_fee",
    "parcel_delivery": "delivery_claim", "customs_fee": "delivery_claim", "marketplace_buyer": "money_transfer",
    "ecommerce_non_delivery": "money_transfer", "fake_online_shop": "money_transfer",
    "fake_friend": "friend_new_number", "family_emergency": "friend_new_number", "romance": "money_transfer",
    "wrong_number": "friend_new_number", "dating_verification": "advance_fee",
    "prize_lottery": "prize", "advance_fee": "advance_fee", "loyalty_points": "prize",
    "survey_reward": "prize", "gift_card": "money_transfer",
    "tech_support": "tech_support", "malware_delivery": "tech_support", "subscription_refund": "tech_support",
    "qr_payment": "money_transfer", "deepfake_impersonation": "money_transfer",
    "rental": "rental_offer", "travel_booking": "advance_fee", "ticketing": "advance_fee",
    "pet_adoption": "advance_fee", "legal_services": "advance_fee",
    "healthcare_medical": "money_transfer", "insurance": "secret_request", "charity": "money_transfer",
    "donation_disaster": "money_transfer", "recovery": "recovery_offer",
    "blackmail_sextortion": "money_transfer", "utility_disconnection": "urgency",
    "toll_parking": "money_transfer", "mobile_topup": "money_transfer", "callback_premium": "urgency",
}


def digest(value: str, length: int = 20) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()[:length]


def taxonomy() -> list[dict]:
    macro = (
        "account_identity", "authority_coercion", "financial_services", "investment_crypto",
        "work_business", "commerce_delivery", "personal_relationship", "reward_advance_fee",
        "technology_subscription", "property_travel_services", "health_charity_recovery",
        "threat_billing_utilities",
    )
    rows = []
    for index, spec in enumerate(FAMILY_SPECS):
        family_id, name, pretext, objective, sector, action = spec
        rows.append({
            "id": family_id, "name": name, "macro_category": macro[index // 5],
            "description": f"Uses {pretext} to pursue {objective}.",
            "pretext": pretext, "objective": objective, "impersonated_sector": sector,
            "requested_action": action, "anchor_required": True,
            "pattern_outcome": "identified", "version": TAXONOMY_VERSION,
        })
    return rows


def languages() -> list[dict]:
    rows = []
    for seed in LANGUAGE_SEEDS:
        code, name, script, urgent, verify, pay, secret, contact, benign, awareness = seed
        has_curated_anchors = code in CURATED_ANCHORS
        rows.append({
            "code": code, "name": name, "script": script,
            "coverage_tier": "A" if has_curated_anchors else "B",
            "native_review_status": "not_reviewed",
            "seed_method": "curated_anchor_pack" if has_curated_anchors else "generic_seed_only",
            "phrases": {"urgent": urgent, "verify": verify, "pay": pay, "secret": secret,
                        "contact": contact, "benign": benign, "awareness": awareness},
        })
    return rows


def split_for_variant(variant: int) -> str:
    """Hold complete campaign/template variants out of training."""
    if not isinstance(variant, int) or isinstance(variant, bool) or not 0 <= variant < 20:
        raise ValueError("variant must be an integer from 0 through 19")
    return "train" if variant < 16 else "development" if variant < 18 else "test"


def defanged_url(index: int, path: str) -> str:
    return f"hxxps://example-{index % 997}[.]invalid/{path}/{index % 10000:04d}"


def adversarial(text: str, mode: str) -> str:
    if mode == "percent_encoding":
        return text.replace("/verify/", "/%76%65%72%69%66%79/")
    urls: list[str] = []

    def protect_url(match: re.Match) -> str:
        urls.append(match.group(0))
        return f"\ufff0{len(urls) - 1}\ufff1"

    protected = re.sub(r"hxxps://\S+", protect_url, text)
    if mode == "leetspeak":
        protected = protected.replace("a", "4").replace("e", "3").replace("o", "0")
    elif mode == "zero_width":
        protected = protected.replace(" ", "\u200b ", 3)
    elif mode == "split_tokens":
        protected = protected.replace("account", "a c c o u n t").replace("verify", "v e r i f y")
    elif mode == "mixed_script":
        protected = protected.replace("a", "а", 2).replace("o", "ο", 2)
    else:
        protected = protected.replace("!", "!!!") if "!" in protected else protected + " !!!"
    for position, url in enumerate(urls):
        protected = protected.replace(f"\ufff0{position}\ufff1", url)
    return protected


def arrange(parts: list[str], variant: int) -> str:
    """Render twenty structural families without emitting an identifying tag."""
    orders = (
        (0, 1, 2, 3, 4, 5), (1, 0, 2, 4, 3, 5), (0, 2, 1, 3, 5, 4),
        (2, 0, 1, 4, 3, 5), (1, 2, 0, 3, 4, 5), (0, 1, 3, 2, 4, 5),
        (2, 1, 0, 5, 3, 4), (1, 0, 3, 2, 5, 4), (0, 3, 1, 2, 4, 5),
        (3, 0, 2, 1, 5, 4),
    )
    separators = (". ", " — ")
    order = orders[variant % len(orders)]
    return separators[(variant // len(orders)) % 2].join(parts[position] for position in order if parts[position])


def normalized_cluster(text: str) -> str:
    value = text.casefold()
    value = re.sub(r"hxxps://\S+", "<url>", value)
    value = re.sub(r"\bnv-[0-9-]+\b", "<reference>", value)
    value = re.sub(r"\b\d+(?:[.:]\d+)?\b", "<number>", value)
    value = re.sub(r"\s+", " ", value).strip()
    return "TXT-" + digest(value, 16)


def family_pretext(family: dict, language: str, index: int) -> tuple[str, bool]:
    key = FAMILY_ANCHOR_KEYS[family["id"]]
    values = CURATED_ANCHORS.get(language, {}).get(key, [])
    if values:
        return values[index % len(values)], True
    return family["pretext"], False


def base_record(index: int, kind: str, family: dict, lang: dict) -> dict:
    if not isinstance(index, int) or isinstance(index, bool) or index < 0:
        raise ValueError("index must be a non-negative integer")
    if kind not in ALLOWED_KINDS:
        raise ValueError(f"unknown record kind: {kind!r}")
    p = lang["phrases"]
    channel = CHANNELS[(index // 7) % len(CHANNELS)]
    brand = BRANDS[(index // 11) % len(BRANDS)]
    payment = PAYMENTS[(index // 13) % len(PAYMENTS)]
    lure = LURES[(index // 17) % len(LURES)]
    amount = AMOUNTS[(index // 19) % len(AMOUNTS)]
    deadline = DEADLINES[(index // 23) % len(DEADLINES)]
    path = PATHS[(index // 29) % len(PATHS)]
    template_id = f"{kind}-{index % 120:03d}"
    # A campaign deliberately groups multiple surface variants. Keeping kind out
    # of the key prevents related scam, adversarial, conversation and control
    # records from leaking across train/development/test partitions.
    campaign_variant = (index // (len(LANGUAGE_SEEDS) * len(FAMILY_SPECS))) % 20
    campaign_key = f"{lang['code']}|{family['id']}|{campaign_variant}"
    campaign_id = "CMP-" + digest(campaign_key, 16)
    template_cluster_id = f"TPL-{kind}-{campaign_variant:02d}"
    near_duplicate_cluster_id = "ND-" + digest(f"{lang['code']}|{family['id']}|{kind}|{campaign_variant}", 16)
    split = split_for_variant(campaign_variant)
    reference = f"NV-{index % 1_000_000:06d}-{(index * 17) % 997:03d}"
    url = defanged_url(index, path)
    style_cue = STYLE_CUES[campaign_variant]
    pretext, localized_anchor_used = family_pretext(family, lang["code"], index)

    if kind == "scam":
        text = arrange([p["urgent"], f"{brand}: {pretext}", p["verify"],
                        f"{p['pay']} {amount} via {payment}", f"within {deadline}",
                        f"{url} Ref {reference}"], campaign_variant)
        label, outcome, evasions, stage = "scam", "identified", [], "action_request"
    elif kind == "adversarial_scam":
        raw = arrange([p["urgent"], f"{brand}: {pretext}", p["verify"],
                       p["secret"], f"within {deadline}", f"{url} Ref {reference}"], campaign_variant)
        mode = EVASIONS[index % len(EVASIONS)]
        text = adversarial(raw, mode)
        label, outcome, evasions, stage = "adversarial_scam", "identified", [mode], "action_request"
    elif kind == "hard_negative":
        text = arrange([p["awareness"], "Training example", family["name"],
                        f"may mention '{pretext}'", f"never {family['requested_action']}",
                        f"Ref {reference}"], campaign_variant)
        label, outcome, evasions, stage = "hard_negative", "none", [], "awareness"
    elif kind == "conversation_turn":
        stages = ("contact", "trust_building", "pretext", "pressure", "action_request")
        stage = stages[index % len(stages)]
        if stage == "contact":
            text = arrange([p["contact"], brand, pretext, "", "", f"Ref {reference}"], campaign_variant)
        elif stage == "trust_building":
            text = arrange([brand, p["verify"], "This conversation is confidential", "", "", f"Ref {reference}"], campaign_variant)
        elif stage == "pretext":
            text = arrange([pretext, p["urgent"], "", "", "", f"Ref {reference}"], campaign_variant)
        elif stage == "pressure":
            text = arrange([p["urgent"], f"respond within {deadline}", "", "", "", f"Ref {reference}"], campaign_variant)
        else:
            text = arrange([p["pay"], amount, payment, url, "", f"Ref {reference}"], campaign_variant)
        outcome = "identified" if stage == "action_request" else "undetermined"
        label, evasions = "conversation_turn", []
    else:
        text = arrange([p["benign"], brand, f"scheduled {family['impersonated_sector']} update",
                        "no payment is requested", "no password or security code is requested",
                        f"Ref {reference}"], campaign_variant)
        label, outcome, evasions, stage = "benign", "none", [], "legitimate_notice"

    # The cue is part of the surface structure, not metadata. Variants 16–19
    # are absent from training, so development/test measure unseen wording.
    text = f"{style_cue}. {text}"

    record_key = f"{VERSION}|{kind}|{index}|{lang['code']}|{family['id']}|{template_id}"
    family_identified = kind in {"scam", "adversarial_scam"} or (
        kind == "conversation_turn" and outcome == "identified"
    )
    action_observed = kind in {"scam", "adversarial_scam"} or (
        kind == "conversation_turn" and stage == "action_request"
    )
    return {
        "record_id": "NVDS-" + digest(record_key),
        "text": text,
        "label": label,
        "pattern_outcome": outcome,
        "scam_family": family["id"] if family_identified else None,
        "scenario_family": family["id"] if kind != "benign" else None,
        "macro_category": family["macro_category"] if family_identified else None,
        "language": lang["code"], "language_name": lang["name"], "script": lang["script"],
        "language_form": "curated_anchor_with_international_terms" if localized_anchor_used else "localized_seed_with_international_technical_terms",
        "language_quality_tier": lang["coverage_tier"],
        "native_review_status": lang["native_review_status"],
        "channel": channel, "conversation_stage": stage,
        "pretext": pretext if kind != "benign" else None,
        "requested_action": family["requested_action"] if action_observed else None,
        "objective": family["objective"] if action_observed else None,
        "impersonated_sector": family["impersonated_sector"],
        "payment_method": payment if action_observed else None,
        "lure": lure if kind in {"scam", "adversarial_scam"} or stage in {"pressure", "action_request"} else None,
        "evasion_types": evasions,
        "contains_defanged_url": "hxxps://" in text,
        "campaign_id": campaign_id, "template_cluster_id": template_cluster_id,
        "near_duplicate_cluster_id": near_duplicate_cluster_id,
        "normalized_text_cluster_id": normalized_cluster(text), "split": split,
        "template_id": template_id, "source_type": "synthetic",
        "generation_method": GENERATOR_VERSION, "taxonomy_version": TAXONOMY_VERSION,
        "licence": LICENSE, "pii_present": False, "safety_status": "defanged",
        "quality_flags": ["synthetic", "native_review_pending", "international_terms_present"] + (["curated_anchor_pack"] if localized_anchor_used else ["generic_seed_only"]),
    }


def schema() -> dict:
    properties = {
        "record_id": {"type": "string", "pattern": "^NVDS-[0-9a-f]{20}$"},
        "text": {"type": "string", "minLength": 1, "maxLength": 1200},
        "label": {"enum": list(DEFAULT_COUNTS)},
        "pattern_outcome": {"enum": ["identified", "undetermined", "none"]},
        "scam_family": {"type": ["string", "null"]},
        "scenario_family": {"type": ["string", "null"]},
        "macro_category": {"type": ["string", "null"]},
        "language": {"type": "string"},
        "language_name": {"type": "string"},
        "script": {"type": "string"},
        "language_form": {"type": "string"},
        "language_quality_tier": {"enum": ["A", "B"]},
        "native_review_status": {"enum": ["not_reviewed", "sample_reviewed", "fully_reviewed"]},
        "channel": {"enum": list(CHANNELS)},
        "conversation_stage": {"enum": ["contact", "trust_building", "pretext", "pressure", "action_request", "awareness", "legitimate_notice"]},
        "pretext": {"type": ["string", "null"]},
        "requested_action": {"type": ["string", "null"]},
        "objective": {"type": ["string", "null"]},
        "impersonated_sector": {"type": "string"},
        "payment_method": {"type": ["string", "null"]},
        "lure": {"type": ["string", "null"]},
        "evasion_types": {"type": "array", "items": {"type": "string"}},
        "contains_defanged_url": {"type": "boolean"},
        "campaign_id": {"type": "string", "pattern": "^CMP-[0-9a-f]{16}$"},
        "template_cluster_id": {"type": "string", "pattern": "^TPL-[a-z_]+-(0[0-9]|1[0-9])$"},
        "near_duplicate_cluster_id": {"type": "string", "pattern": "^ND-[0-9a-f]{16}$"},
        "normalized_text_cluster_id": {"type": "string", "pattern": "^TXT-[0-9a-f]{16}$"},
        "split": {"enum": ["train", "development", "test"]},
        "template_id": {"type": "string"},
        "source_type": {"enum": ["synthetic", "public_source", "consented_real", "translated"]},
        "generation_method": {"type": "string"},
        "taxonomy_version": {"type": "string"},
        "licence": {"const": LICENSE},
        "pii_present": {"const": False},
        "safety_status": {"const": "defanged"},
        "quality_flags": {"type": "array", "items": {"type": "string"}},
    }
    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "title": "NexVision ScamText Global record",
        "type": "object",
        "required": list(properties),
        "properties": properties,
        "additionalProperties": False,
    }


def file_sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def write_json_atomic(path: Path, payload: object) -> None:
    """Write JSON completely before replacing a release metadata file."""
    temporary = path.with_suffix(path.suffix + ".tmp")
    with temporary.open("w", encoding="utf-8") as handle:
        json.dump(payload, handle, ensure_ascii=False, indent=2)
        handle.write("\n")
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(temporary, path)


def label_schedule(records: int) -> list[tuple[str, int]]:
    """Allocate an exact, non-negative class mix using largest remainders."""
    total = sum(DEFAULT_COUNTS.values())
    if records == total:
        return list(DEFAULT_COUNTS.items())
    allocated: dict[str, int] = {}
    remainders: list[tuple[int, int, str]] = []
    for position, (name, weight) in enumerate(DEFAULT_COUNTS.items()):
        numerator = records * weight
        allocated[name] = numerator // total
        remainders.append((numerator % total, -position, name))
    remaining = records - sum(allocated.values())
    for _, _, name in sorted(remainders, reverse=True)[:remaining]:
        allocated[name] += 1
    return [(name, allocated[name]) for name in DEFAULT_COUNTS]


def finalize_shard(handle, temporary: Path, destination: Path, expected_rows: int) -> None:
    """Close, fsync, verify and atomically install one compressed shard."""
    handle.flush()
    handle.close()
    # Open read-write: on Windows, fsync (FlushFileBuffers) fails with EBADF on
    # a read-only descriptor, while POSIX accepts either.
    descriptor = os.open(temporary, os.O_RDWR | getattr(os, "O_BINARY", 0))
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    with gzip.open(temporary, "rt", encoding="utf-8") as check:
        observed_rows = sum(1 for _ in check)
    if observed_rows != expected_rows:
        raise RuntimeError(f"incomplete shard {destination.name}: {observed_rows}/{expected_rows}")
    os.replace(temporary, destination)


def _generate_release(output: Path, records: int, shard_size: int) -> dict:
    output.mkdir(parents=True, exist_ok=True)
    shards_dir = output / "shards"
    shards_dir.mkdir(parents=True, exist_ok=True)
    tax = taxonomy()
    langs = languages()
    family_ids = {row["id"] for row in tax}
    language_codes = {row["code"] for row in langs}
    if len(tax) != 60 or len(family_ids) != 60 or len(langs) != 50 or len(language_codes) != 50:
        raise RuntimeError("taxonomy/language registry cardinality regression")
    if set(FAMILY_ANCHOR_KEYS) != family_ids:
        raise RuntimeError("family-to-anchor mapping does not match the taxonomy")
    if not set(CURATED_ANCHORS).issubset(language_codes):
        raise RuntimeError("anchor pack contains an unknown language")

    write_json_atomic(output / "taxonomy.json", tax)
    write_json_atomic(output / "language_registry.json", langs)
    write_json_atomic(output / "schema.json", schema())
    # Copy the source anchor pack into every generated release, including
    # temporary test releases, so the manifest is self-contained.
    write_json_atomic(output / "curated_anchor_packs.json", CURATED_ANCHOR_PAYLOAD)
    provenance = {
        "dataset": "NexVision ScamText Global", "version": VERSION,
        "created": RELEASE_DATE, "offline_generation": True, "runtime_api_calls": False,
        "source_types": {"synthetic": records}, "contains_real_messages": False,
        "contains_personal_data": False, "url_policy": "hxxps and bracketed .invalid domains only",
        "licence": LICENSE,
        "warning": "Synthetic data is not external validation and language quality is not uniform.",
        "curated_anchor_pack_languages": len(CURATED_ANCHORS),
        "curated_anchor_pack_source": "NexVision OSINT Scam Message Checker v1.2.0",
    }
    write_json_atomic(output / "provenance.json", provenance)

    schedule = label_schedule(records)

    label_counts, outcome_counts = Counter(), Counter()
    language_counts, family_counts, split_counts = Counter(), Counter(), Counter()
    label_language_counts, language_family_counts = Counter(), Counter()
    campaign_splits: dict[str, str] = {}
    template_splits: dict[str, str] = {}
    near_duplicate_splits: dict[str, str] = {}
    normalized_text_splits: dict[str, str] = {}
    preview_path = output / "preview.jsonl"
    preview_temporary = preview_path.with_suffix(preview_path.suffix + ".tmp")
    preview = preview_temporary.open("w", encoding="utf-8")
    shard_paths: list[Path] = []
    shard = None
    temporary_path = None
    destination_path = None
    current_shard_rows = 0
    global_index = 0
    try:
        for kind, count in schedule:
            for _ in range(count):
                if global_index % shard_size == 0:
                    if shard is not None:
                        finalize_shard(shard, temporary_path, destination_path, current_shard_rows)
                    path = shards_dir / f"part-{len(shard_paths):05d}.jsonl.gz"
                    shard_paths.append(path)
                    destination_path = path
                    temporary_path = path.with_suffix(path.suffix + ".tmp")
                    shard = gzip.open(temporary_path, "wt", encoding="utf-8", compresslevel=6)
                    current_shard_rows = 0
                lang = langs[global_index % len(langs)]
                # Every consecutive 3,000-record block covers each of the
                # 50 language × 60 family cells exactly once.
                family = tax[(global_index // len(langs)) % len(tax)]
                row = base_record(global_index, kind, family, lang)
                existing = campaign_splits.setdefault(row["campaign_id"], row["split"])
                if existing != row["split"]:
                    raise RuntimeError("campaign split leakage")
                for mapping, field, label in (
                    (template_splits, "template_cluster_id", "template"),
                    (near_duplicate_splits, "near_duplicate_cluster_id", "near-duplicate"),
                    (normalized_text_splits, "normalized_text_cluster_id", "normalized-text"),
                ):
                    existing = mapping.setdefault(row[field], row["split"])
                    if existing != row["split"]:
                        raise RuntimeError(f"{label} split leakage")
                line = json.dumps(row, ensure_ascii=False, separators=(",", ":"))
                shard.write(line + "\n")
                current_shard_rows += 1
                if global_index < 500:
                    preview.write(json.dumps(row, ensure_ascii=False) + "\n")
                label_counts[row["label"]] += 1
                outcome_counts[row["pattern_outcome"]] += 1
                language_counts[row["language"]] += 1
                label_language_counts[(row["language"], row["label"])] += 1
                split_counts[row["split"]] += 1
                if row["scenario_family"]:
                    family_counts[row["scenario_family"]] += 1
                    language_family_counts[(row["language"], row["scenario_family"])] += 1
                global_index += 1
        if shard is not None and not shard.closed:
            finalize_shard(shard, temporary_path, destination_path, current_shard_rows)
            shard = None
        preview.flush()
        os.fsync(preview.fileno())
        preview.close()
        os.replace(preview_temporary, preview_path)
    except BaseException:
        if shard is not None and not shard.closed:
            shard.close()
        if temporary_path is not None and temporary_path.exists():
            temporary_path.unlink()
        if not preview.closed:
            preview.close()
        if preview_temporary.exists():
            preview_temporary.unlink()
        raise

    expected_shards = {path.resolve() for path in shard_paths}
    for stale in shards_dir.glob("part-*.jsonl.gz"):
        if stale.resolve() not in expected_shards:
            stale.unlink()
    for stale in shards_dir.glob("*.tmp"):
        stale.unlink()

    quality_report = {
        "version": VERSION, "records": global_index,
        "language_balance": {"minimum": min(language_counts.values()), "maximum": max(language_counts.values())},
        "family_balance": {"minimum": min(family_counts.values()), "maximum": max(family_counts.values())},
        "language_family_pairs_observed": len(language_family_counts),
        "language_family_pairs_expected": len(langs) * len(tax),
        "campaign_clusters": len(campaign_splits), "template_clusters": len(template_splits),
        "near_duplicate_clusters": len(near_duplicate_splits),
        "normalized_text_clusters": len(normalized_text_splits),
        "campaign_split_leakage": 0, "template_split_leakage": 0,
        "near_duplicate_split_leakage": 0, "normalized_text_split_leakage": 0,
        "native_reviewed_languages": 0, "synthetic_fraction": 1.0,
        "curated_anchor_pack_languages": len(CURATED_ANCHORS),
        "generic_seed_only_languages": len(langs) - len(CURATED_ANCHORS),
        "deployment_status": "research_only_external_validation_required",
        "label_language_counts": {
            code: {label: label_language_counts[(code, label)] for label in DEFAULT_COUNTS}
            for code in sorted(language_counts)
        },
    }
    write_json_atomic(output / "quality_report.json", quality_report)

    files = []
    for path in [output / "taxonomy.json", output / "language_registry.json", output / "schema.json",
                 output / "provenance.json", output / "quality_report.json", output / "curated_anchor_packs.json",
                 output / "preview.jsonl", *shard_paths]:
        files.append({"path": path.relative_to(output).as_posix(), "bytes": path.stat().st_size, "sha256": file_sha256(path)})
    manifest = {
        "dataset": "NexVision ScamText Global", "version": VERSION,
        "records": global_index, "taxonomy_families": len(tax), "macro_categories": 12,
        "languages": len(langs), "scripts": len({x["script"] for x in langs}),
        "label_counts": dict(label_counts), "language_counts": dict(language_counts),
        "pattern_outcome_counts": dict(outcome_counts),
        "family_counts": dict(family_counts), "split_counts": dict(split_counts),
        "campaigns": len(campaign_splits), "template_clusters": len(template_splits),
        "near_duplicate_clusters": len(near_duplicate_splits),
        "normalized_text_clusters": len(normalized_text_splits),
        "campaign_split_leakage": 0, "template_split_leakage": 0,
        "near_duplicate_split_leakage": 0, "normalized_text_split_leakage": 0,
        "language_family_pairs": len(language_family_counts),
        "language_family_pairs_expected": len(langs) * len(tax),
        "language_family_coverage_complete": len(language_family_counts) == len(langs) * len(tax),
        "native_review_status": {"not_reviewed": len(langs)}, "files": files,
    }
    write_json_atomic(output / "manifest.json", manifest)
    return manifest


def validate_output_target(output: Path) -> Path:
    """Resolve an output path without allowing unrelated data to be replaced."""
    candidate = Path(output).expanduser()
    if candidate.is_symlink():
        raise ValueError(f"output must not be a symbolic link: {candidate}")
    resolved = candidate.resolve()
    if resolved == Path(resolved.anchor):
        raise ValueError("output must not be a filesystem root")
    if not resolved.exists():
        return resolved
    if not resolved.is_dir():
        raise ValueError(f"output exists and is not a directory: {resolved}")
    if not any(resolved.iterdir()):
        return resolved
    manifest_path = resolved / "manifest.json"
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError(
            f"refusing to replace nonempty unmanaged output directory: {resolved}"
        ) from exc
    if not isinstance(manifest, dict) or manifest.get("dataset") not in MANAGED_DATASET_NAMES:
        raise ValueError(f"refusing to replace nonempty unmanaged output directory: {resolved}")
    return resolved


def generate(output: Path, records: int, shard_size: int) -> dict:
    """Generate in a sibling directory and atomically promote the release."""
    if not isinstance(records, int) or isinstance(records, bool) or records < 1:
        raise ValueError("records must be a positive integer")
    if not isinstance(shard_size, int) or isinstance(shard_size, bool) or shard_size < 1:
        raise ValueError("shard_size must be a positive integer")
    output = validate_output_target(output)
    output.parent.mkdir(parents=True, exist_ok=True)

    staging = Path(tempfile.mkdtemp(prefix=f".{output.name}.generate-", dir=output.parent))
    backup: Path | None = None
    try:
        manifest = _generate_release(staging, records, shard_size)
        if output.exists():
            backup = Path(tempfile.mkdtemp(prefix=f".{output.name}.backup-", dir=output.parent))
            backup.rmdir()
            os.replace(output, backup)
        try:
            os.replace(staging, output)
        except BaseException:
            if backup is not None and backup.exists() and not output.exists():
                os.replace(backup, output)
            raise
        if backup is not None:
            shutil.rmtree(backup)
        return manifest
    finally:
        if staging.exists():
            shutil.rmtree(staging)


SPLIT_BLOCK = len(LANGUAGE_SEEDS) * len(FAMILY_SPECS)  # records per structural variant


def empty_splits(manifest: dict) -> list[str]:
    """Splits with no records in a build (variants 16-19 only start late in the run)."""
    return [name for name in ("train", "development", "test") if not manifest["split_counts"].get(name)]


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--records", type=int, default=1_500_000)
    parser.add_argument("--shard-size", type=int, default=100_000)
    args = parser.parse_args()
    if args.records < 1 or args.shard_size < 1:
        parser.error("record and shard sizes must be positive")
    manifest = generate(args.output, args.records, args.shard_size)
    print(json.dumps({k: manifest[k] for k in ("records", "taxonomy_families", "languages", "scripts", "label_counts", "split_counts")}, indent=2))
    missing = empty_splits(manifest)
    if missing:
        print(f"warning: no {' or '.join(missing)} records in this build; the held-out splits only "
              f"begin after {16 * SPLIT_BLOCK:,} (development) and {18 * SPLIT_BLOCK:,} (test) records, "
              f"so use --records above {18 * SPLIT_BLOCK:,} for a build that includes them.", file=sys.stderr)


if __name__ == "__main__":
    main()
