# وصل - Wasl (Backend)


## 💡 فكرة المشروع
وصل هو نظام خدمات إلكتروني يساعد الشركات على تقديم خدماتها للعملاء بطريقة أكثر احترافية وتنظيمًا. من خلال المنصة، يمكن للعملاء طلب خدمات، وتتبع حالة الطلب، والتواصل مع الموظفين. كما تتيح للموظفين والإداريين إدارة الطلبات والمحتوى بشكل فعال عبر واجهات مخصصة حسب كل دور.

---

## نظرة عامة
وصل هو مشروع ويب يهدف إلى تقديم منصة خدمات شاملة تساعد الشركات على تقديم خدماتها بشكل ميسر للعملاء. يتضمن المشروع واجهات للمستخدمين (عملاء، موظفين، ومديرين) لطلب الخدمات، متابعة الطلبات، وإدارة المحتوى.

---

## 🧪 رابط Postman
📬 يمكنك تجربة واختبار جميع الـ APIs عبر Postman:

🔗 [Postman Collection](https://gold-water-567594.postman.co/workspace/My-Workspace~8e6e5921-d4ac-410b-8a32-4fbfdeb96b39/collection/19264943-db494110-b07d-4bb5-9722-95944fc285a3?action=share&creator=19264943)


---

## 🌐 رابط النسخة المباشرة (Live API)
يمكنك الوصول إلى الـ API المرفوعة من خلال الرابط التالي:

🔗 [https://web-production-98c0.up.railway.app/](https://web-production-98c0.up.railway.app/)

---

## التقنيات المستخدمة
- **Django** - إطار العمل المستخدم لتطوير التطبيق الخلفي.
- **Django REST Framework** - لبناء API RESTful بسهولة.
- **Django CORS Headers** - لإدارة الـ Cross-Origin Resource Sharing (CORS).
- **Django Filter** - لتصفية البيانات عبر API.
- **Django JWT Authentication** - لإدارة المصادقة باستخدام JWT.
- **SQLite** - قاعدة بيانات مدمجة لخدمات المشروع.
- **Gunicorn** - خادم WSGI لتشغيل تطبيق Django.
- **Whitenoise** - لتوفير ملفات static في الإنتاج.

## متطلبات النظام 
- **Python 3.12.0** - نسخة Python المطلوبة لتشغيل المشروع.
- **Django 5.1.3**
- **Django REST Framework**
- **SQLite** 

## كيفية التشغيل المحلي
لتشغيل المشروع محليًا، اتبع الخطوات التالية:

### 1. تثبيت الاعتمادات:
أولاً، تأكد من أنك في البيئة الافتراضية (virtual environment)، ثم قم بتثبيت الاعتمادات:

```
pip install -r requirements.txt
```
### 2. إعداد قاعدة البيانات:
قم بترحيل قاعدة البيانات:
```
python manage.py migrate
```
### 3. إنشاء المستخدم الإداري (Superuser):
```
python manage.py createsuperuser
```
### 4. تشغيل الخادم المحلي:
لتشغيل الخادم المحلي:
```
python manage.py runserver
```
ثم قم بفتح المتصفح الخاص بك وتوجه إلى:

```
http://127.0.0.1:8000
```

---
## 🧪 حسابات تجريبية (Test Accounts)

#### 👤 عميل (Client)
- **اسم المستخدم:** `mohamed1654`
- **البريد الإلكتروني:** `client@wasl.com`  
- **كلمة المرور:** `newPass123`

#### 👨‍🔧 موظف (Employee)
- **اسم المستخدم:** `ali123`
- **البريد الإلكتروني:** `employee@wasl.com`  
- **كلمة المرور:** `newPass123`

#### 👑 أدمن (Admin)
- **اسم المستخدم:** `admin`
- **البريد الإلكتروني:** `admin@wasl.com`  
- **كلمة المرور:** `admin123`

---

# Wasl - Backend

## 💡 Project Idea
Wasl is an electronic service system that helps companies provide their services to clients in a more professional and organized way. Through the platform, clients can request services, track order status, and communicate with employees. It also allows employees and administrators to manage orders and content efficiently through role-based dashboards.

---

## Overview
Wasl is a web project aimed at providing a comprehensive service platform that helps businesses easily offer their services to clients. The project includes interfaces for users (clients, employees, and admins) to request services, track orders, and manage content.

---

## 🧪 Postman Link
📬 You can explore and test all the APIs via Postman:

🔗 [Postman Collection](https://gold-water-567594.postman.co/workspace/My-Workspace~8e6e5921-d4ac-410b-8a32-4fbfdeb96b39/collection/19264943-db494110-b07d-4bb5-9722-95944fc285a3?action=share&creator=19264943)

---

## 🌐 Live API Link
You can access the deployed API through the following link:

🔗 [https://web-production-98c0.up.railway.app/](https://web-production-98c0.up.railway.app/)

---

## ⚙️ Technologies Used
- **Django** – Backend web framework used to develop the application
- **Django REST Framework** – For building RESTful APIs
- **Django CORS Headers** – For managing Cross-Origin Resource Sharing (CORS)
- **Django Filter** – For filtering data through the API
- **Django JWT Authentication** – For handling authentication using JWT
- **SQLite** – Embedded database for the project services
- **Gunicorn** – WSGI server to run the Django application
- **Whitenoise** – For serving static files in production

---

## 📋 System Requirements
- **Python 3.12.0** – Required Python version to run the project
- **Django 5.1.3**
- **Django REST Framework**
- **SQLite**

---

## 🚀 Running Locally

To run the project locally, follow these steps:

### 1. Install Dependencies:
Make sure you are in the virtual environment, then install the dependencies:

```
pip install -r requirements.txt
```
### 2. Set Up the Database:
Run the migrations:
```
python manage.py migrate
```
### 3. Create a Superuser:
```
python manage.py createsuperuser
```
### 4. Start the Local Server:
To run the local server:
```
python manage.py runserver
```
Then, open your browser and go to:
```
http://127.0.0.1:8000
```
---

## 🧪 Test Accounts

#### 👤 Client
- **Username:** `mohamed1654`
- **Email:** `client@wasl.com`  
- **Password:** `newPass123`

#### 👨‍🔧 Employee
- **Username:** `ali123`
- **Email:** `employee@wasl.com`  
- **Password:** `newPass123`

#### 👑 Admin
- **Username:** `admin`
- **Email:** `admin@wasl.com`  
- **Password:** `admin123`

---