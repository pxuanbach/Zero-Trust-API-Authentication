# Đề Xuất Kiến Trúc Zero-Trust API Authentication: Kết Hợp mTLS và Token-Based Signatures

## Bảng từ viết tắt

| Từ viết tắt | Từ đầy đủ |
|-------------|-----------|
| **API** | Application Programming Interface |
| **mTLS** | Mutual Transport Layer Security |
| **TLS** | Transport Layer Security |
| **PoP** | Proof of Possession |
| **DPoP** | Demonstrating Proof of Possession |
| **HoK** | Holder of Key |
| **JWT** | JSON Web Token |
| **PKI** | Public Key Infrastructure |
| **CA** | Certificate Authority |
| **CSR** | Certificate Signing Request |
| **ECDSA** | Elliptic Curve Digital Signature Algorithm |
| **RSA** | Rivest-Shamir-Adleman |
| **AWS** | Amazon Web Services |
| **EC2** | Elastic Compute Cloud |
| **RDS** | Relational Database Service |
| **ALB** | Application Load Balancer |
| **KMS** | Key Management Service |
| **ACM** | AWS Certificate Manager |
| **OCSP** | Online Certificate Status Protocol |
| **CRL** | Certificate Revocation List |
| **XSS** | Cross-Site Scripting |
| **MitM** | Man-in-the-Middle |
| **NIST** | National Institute of Standards and Technology |
| **RFC** | Request for Comments |
| **FAPI** | Financial-grade API |
| **PSD2** | Payment Services Directive 2 |
| **GDPR** | General Data Protection Regulation |
| **PCI DSS** | Payment Card Industry Data Security Standard |
| **SOX** | Sarbanes-Oxley Act |

## 1. Introduction

Trong bối cảnh bảo mật hiện đại, các tổ chức ngày càng chuyển sang mô hình Zero-Trust để bảo vệ tài sản kỹ thuật số. Đặc biệt, với sự bùng nổ của microservices và kiến trúc điều khiển bằng API, việc xác thực và ủy quyền API trở thành một thách thức quan trọng. Các phương pháp xác thực truyền thống như token mang (Bearer) có nhiều hạn chế về bảo mật, đặc biệt là khả năng bị đánh cắp token và tấn công phát lại (replay).

Nghiên cứu này đề xuất một kiến trúc xác thực API Zero-Trust kết hợp TLS tương hỗ (mTLS) với chữ ký dựa trên token, cụ thể là token chứng minh sở hữu (PoP), nhằm tạo ra một hệ thống xác thực đa lớp có khả năng chống lại các cuộc tấn công đánh cắp token và tấn công phát lại. Kiến trúc được thiết kế để triển khai trên môi trường đám mây AWS với trọng tâm vào việc so sánh hiệu suất của các thuật toán mã hóa khác nhau.

### Mục tiêu nghiên cứu:
- Xây dựng một API proxy gateway với Zero-Trust authentication
- So sánh hiệu suất của các thuật toán mã hóa (ECDSA, RSA, Ed25519) trong môi trường thực tế
- Đánh giá tính hiệu quả của việc kết hợp mTLS và token-based signatures
- Đề xuất các chiến lược vận hành PKI tối ưu cho môi trường cloud

## 2. Theoretical Basis

### 2.1 Definition

#### Zero-Trust Architecture
Zero-Trust là một mô hình bảo mật dựa trên nguyên tắc "never trust, always verify" (không bao giờ tin tưởng, luôn xác minh). Trong bối cảnh API security, Zero-Trust yêu cầu:
- Xác thực và ủy quyền mọi request API
- Kiểm tra liên tục danh tính và quyền hạn
- Giảm thiểu diện tấn công thông qua truy cập đặc quyền tối thiểu
- Giám sát và audit toàn diện mọi giao dịch

#### Mutual TLS (mTLS)
mTLS là một extension của TLS protocol trong đó cả client và server đều phải xác thực lẫn nhau thông qua digital certificates:
- **Transport Layer Security**: Mã hóa giao tiếp đầu cuối
- **Bidirectional Authentication**: Cả hai bên đều xác minh danh tính
- **Certificate-based Identity**: Sử dụng cơ sở hạ tầng PKI cho xác thực mạnh
- **Perfect Forward Secrecy**: Bảo vệ dữ liệu quá khứ nếu khóa riêng tư bị xâm phạm

#### Token-Based Signatures (Proof of Possession)
Token chứng minh sở hữu (PoP) là một cơ chế xác thực trong đó client phải chứng minh việc sở hữu khóa mã hóa được liên kết với token truy cập:
- **DPoP (Demonstrating Proof of Possession)**: Client tạo bằng chứng JWT ký bằng khóa riêng tư
- **Holder-of-Key (HoK)**: Token được ràng buộc với khóa mã hóa cụ thể
- **Ngăn tấn công phát lại**: Mỗi yêu cầu cần bằng chứng mã hóa mới
- **Ràng buộc Token**: Liên kết token với chứng chỉ hoặc khóa công khai

### 2.2 Motivation

#### Các hạn chế của phương pháp hiện tại

**Bearer Token Vulnerabilities:**
```
Threat Model:
┌─────────────┐    ┌─────────────┐    ┌─────────────┐
│   Client    │───▶│  Attacker   │───▶│ API Server  │
│ Application │    │   (MitM)    │    │             │
└─────────────┘    └─────────────┘    └─────────────┘
                         │
                   Đánh cắp Token &
                   Unauthorized Use
```

1. **Token Theft**: Token mang có thể bị đánh cắp thông qua XSS, malware, hoặc chặn bắt mạng
2. **Replay Attacks**: Token bị đánh cắp có thể được sử dụng lại mà không cần xác thực bổ sung
3. **No Cryptographic Binding**: Token không được liên kết với danh tính client cụ thể
4. **Wide Attack Surface**: Token có hiệu lực ở bất kỳ đâu chúng được xuất trình

**TLS-Only Limitations:**
1. **Single Point of Failure**: Chỉ dựa vào xác thực chứng chỉ máy chủ
2. **No Client Authentication**: Không thể xác minh danh tính client
3. **Certificate Pinning Challenges**: Khó triển khai và duy trì trong môi trường động

#### Nhu cầu về Enhanced Security
Với sự gia tăng của các cuộc tấn công tinh vi và yêu cầu tuân thủ (PCI DSS, SOX, GDPR), các tổ chức cần:
- Xác thực đa yếu tố cho truy cập API
- Ràng buộc danh tính mã hóa mạnh
- Nhật ký kiểm toán toàn diện  
- Giảm phạm vi thiệt hại khi vi phạm bảo mật xảy ra

### 2.3 Công trình liên quan

#### Academic Research

Lĩnh vực bảo mật API đã có nhiều tiến bộ quan trọng thông qua các tiêu chuẩn OAuth 2.0 và các phần mở rộng (extensions) của nó. RFC 7800 [1] đã giới thiệu khái niệm Ngữ nghĩa Khóa Chứng minh Sở hữu (Proof-of-Possession Key Semantics) cho JSON Web Tokens, tạo nền tảng cho việc ràng buộc tokens với khóa mật mã. Tiếp theo đó, RFC 9449 [2] chính thức hóa giao thức OAuth 2.0 Demonstrating Proof-of-Possession (DPoP) protocol, cho phép clients chứng minh sở hữu private key thông qua việc tạo bằng chứng động. Đồng thời, RFC 8705 [3] đã chuẩn hóa OAuth 2.0 Mutual-TLS Client Authentication và Certificate-Bound Access Tokens, tạo ra khung làm việc hoàn chỉnh cho xác thực clients mạnh.

Về mặt kiến trúc Zero-Trust, NIST SP 800-207 [4] đã đưa ra định nghĩa chính thức và nguyên tắc triển khai Zero Trust Architecture vào năm 2020. Google đã tiên phong trong việc triển khai practical zero-trust model thông qua sáng kiến BeyondCorp [5], chứng minh khả năng áp dụng "never trust, always verify" principle trong môi trường enterprise quy mô lớn. Microsoft đã mở rộng ý tưởng này với Zero Trust Security Model [6], cung cấp khung làm việc toàn diện bao gồm xác minh danh tính (identity verification), tuân thủ thiết bị (device compliance), và bảo vệ ứng dụng (application protection).

#### Industry Implementations

Ngành tài chính đã dẫn đầu trong việc áp dụng bảo mật API nâng cao. Payment Services Directive 2 (PSD2) [7] của Liên minh Châu Âu đã quy định bắt buộc xác thực clients mạnh cho cho dịch vụ thanh toán, tạo động lực cho việc phát triển hồ sơ bảo mật API cấp độ Tài chính (Financial-grade API - FAPI) [8]. Nhóm Làm việc FAPI tại OpenID Foundation đã phát triển các yêu cầu bảo mật toàn diện sử dụng mTLS và signed JWTs, được nhiều ngân hàng lớn như Barclays, HSBC, và Deutsche Bank áp dụng [9]. SWIFT đã cập nhật các yêu cầu Chương trình Bảo mật Khách hàng (CSP) [10] để bao gồm nhắn tin an toàn với xác thực dựa trên chứng chỉ (certificate-based authentication).

Các công ty công nghệ lớn đã triển khai nhiều phương pháp khác nhau cho xác thực giữa các dịch vụ. Google đã phát triển Istio service mesh [11] với mTLS tự động giữa các services, hiện được sử dụng rộng rãi trong Kubernetes environments. Netflix đã mở mã nguồn Zuul gateway [12] với hỗ trợ cho xác thực dựa trên chứng chỉ, xử lý hàng triệu requests mỗi ngày. Uber đã công bố nghiên cứu điển hình [13] về xác thực dịch vụ nội bộ sử dụng mTLS, báo cáo giảm 99.9% trong sự cố bảo mật. Spotify đã chia sẻ triển khai [14] của **OAuth 2.0 PKCE** với ràng buộc chứng chỉ cho ứng dụng di động.

#### Existing Solutions Analysis

Các giải pháp hiện tại đều có sự đánh đổi riêng biệt. Kong Gateway [15] cung cấp hệ sinh thái plugin phong phú với hỗ trợ mTLS, nhưng thiếu native support cho cơ chế PoP nâng cao và yêu cầu cấu hình phức tạp. Istio Service Mesh [16] mTLS tự động và thực thi chính sách hiệu quả, nhưng bị giới hạn trong môi trường Kubernetes và có đường cong học tập dốc. AWS API Gateway [17] là dịch vụ được quản lý dễ cài đặt, nhưng tùy chọn tùy chỉnh bị hạn chế và tạo ra sự phụ thuộc vào nhà cung cấp. Envoy Proxy [18] cung cấp hiệu suất cao và khả năng mở rộng tốt, nhưng yêu cầu chuyên môn sâu để cấu hình đúng cách.

#### Research Gap

Mặc dù có nhiều khung lý thuyết và triển khai riêng lẻ, vẫn thiếu nghiên cứu toàn diện về tác động hiệu suất của việc kết hợp mTLS với chữ ký dựa trên token trong môi trường sản xuất. Đặc biệt, chưa có so sánh có hệ thống về ảnh hưởng của các thuật toán mã hóa khác nhau (ECDSA, RSA, Ed25519) trên khối lượng công việc thực tế. Tài liệu hiện tại cũng thiếu hướng dẫn thực tế về các khía cạnh vận hành như quản lý vòng đời chứng chỉ, chiến lược xoay khóa, và tối ưu hóa hiệu suất chi phí cho triển khai đám mây.

## 3. Methodology

### 3.1 Proposed Architecture

#### Tổng quan kiến trúc

```
┌─────────────────────────────────────────────────────────────┐
│                        AWS Cloud                             │
│                                                             │
│  ┌─────────────┐    ┌─────────────┐    ┌─────────────┐     │
│  │ Application │───▶│   Private   │    │   AWS KMS   │     │
│  │    Load     │    │   Subnets   │    │  (Keys &    │     │
│  │  Balancer   │    │ (Multi-AZ)  │    │Certificates)│     │
│  └─────────────┘    └─────┬───────┘    └─────────────┘     │
│                           │                                 │
│  ┌─────────────┐    ┌─────▼─────┐    ┌─────────────┐       │
│  │   Secrets   │    │    EC2    │    │ CloudWatch  │       │
│  │  Manager    │    │ Instances │    │(Monitoring) │       │
│  │             │    │ (Proxy)   │    │             │       │
│  └─────────────┘    └───┬───────┘    └─────────────┘       │
│                         │                                  │
│  ┌─────────────┐    ┌───▼───────┐    ┌─────────────┐       │
│  │     RDS     │    │  Backend  │    │ElastiCache  │       │
│  │(PostgreSQL) │    │ Services  │    │  (Redis)    │       │
│  │             │    │(Multi-AZ) │    │             │       │
│  └─────────────┘    └───────────┘    └─────────────┘       │
└─────────────────────────────────────────────────────────────┘
```

**Giải thích chi tiết từng tầng:**

**Tầng Load Balancing:**
Application Load Balancer đóng vai trò là điểm vào chính của hệ thống, thực hiện (1) chấm dứt kết nối SSL/TLS từ phía client; (2) kiểm tra tình trạng sức khỏe của các proxy instances; và (3) phân phối lưu lượng truy cập đều khắp nhiều vùng khả dụng để đảm bảo tính sẵn sàng cao.

**Tầng Compute & Proxy:**
Các EC2 instances được triển khai trong mạng con riêng tư trên nhiều vùng khả dụng, chạy cổng proxy mTLS được phát triển bằng FastAPI với các thư viện (1) cryptography cho xử lý chứng chỉ X.509; (2) PyJWT cho xác thực token; và (3) httpx cho reverse proxy đến các dịch vụ backend. Kiến trúc đa vùng này đảm bảo khả năng chịu lỗi cao và chỉ nhận lưu lượng từ ALB để tăng cường bảo mật.

**Tầng Security & Key Management:**
AWS KMS đảm nhận việc quản lý khóa mã hóa cho chứng chỉ và token thông qua các mô-đun bảo mật phần cứng (HSMs) và cung cấp nhật ký kiểm toán đầy đủ. Secrets Manager lưu trữ an toàn (1) khóa riêng tư của chứng chỉ; (2) thông tin xác thực cơ sở dữ liệu; và (3) khóa API với khả năng tự động xoay vòng để giảm thiểu rủi ro bảo mật.

**Tầng Backend:**
Các dịch vụ logic nghiệp vụ được triển khai trên FastAPI trong mạng con riêng tư với cơ chế cân bằng tải và tự động mở rộng. RDS PostgreSQL hoạt động như cơ sở dữ liệu quan hệ được quản lý với (1) sao lưu tự động; (2) khôi phục đến thời điểm cụ thể; và (3) bản sao đọc để tăng hiệu suất. ElastiCache Redis cung cấp bộ nhớ đệm trong bộ nhớ cho (1) dữ liệu phiên làm việc; (2) kết quả xác thực token; và (3) bộ nhớ đệm xác thực chứng chỉ nhằm giảm độ trễ.

**Tầng Monitoring & Logging:**
CloudWatch thực hiện giám sát toàn diện với các chỉ số, nhật ký và cảnh báo cho các sự kiện hiệu suất và bảo mật. X-Ray hỗ trợ theo dõi phân tán để truy vết luồng yêu cầu qua các dịch vụ, giúp phát hiện và khắc phục sự cố nhanh chóng.

#### Luồng xác thực chi tiết

```
┌─────────────┐         ┌─────────────┐         ┌─────────────┐
│   Client    │         │    mTLS     │         │  Backend    │
│ Application │         │    Proxy    │         │  Service    │
└─────┬───────┘         └─────┬───────┘         └─────┬───────┘
      │                       │                       │
      │ 1. mTLS Handshake     │                       │
      │ + Client Certificate  │                       │
      ├──────────────────────▶│                       │
      │                       │ 2. Certificate        │
      │                       │    Validation         │
      │                       │                       │
      │ 3. HTTP Request       │                       │
      │ + Authorization Header│                       │
      │ + DPoP Proof Header   │                       │
      ├──────────────────────▶│                       │
      │                       │ 4. Xác thực Token     │
      │                       │ 5. Xác minh DPoP      │
      │                       │ 6. Ràng buộc Cert-Token│
      │                       │                       │
      │                       │ 7. Yêu cầu được ủy quyền │
      │                       ├──────────────────────▶│
      │                       │                       │
      │                       │ 8. Response           │
      │                       │◀──────────────────────┤
      │                       │                       │
      │ 9. Response           │                       │
      │◀──────────────────────┤                       │
```

**Cụ thể:**

**Bước 1-2: mTLS Handshake & Xác thực chứng chỉ**
- Client khởi tạo kết nối TLS và gửi chứng chỉ client (X.509) chứa khóa công khai
- Proxy thực hiện xác thực chứng chỉ theo chuỗi:
  ```
  Xác thực chuỗi chứng chỉ:
  ├── Xác minh chữ ký chứng chỉ (sử dụng khóa công khai CA)
  ├── Kiểm tra hạn chứng chỉ (timestamps notBefore/notAfter)
  ├── Kiểm tra trạng thái thu hồi (truy vấn CRL/OCSP)
  ├── Xác thực chính sách chứng chỉ và sử dụng khóa
  └── Xác minh tên thay thế chủ thể (SAN)
  ```
- Nếu xác thực thành công, kênh TLS an toàn được thiết lập với Perfect Forward Secrecy

**Bước 3: HTTP Request với Headers xác thực kép**
Client gửi HTTP request với hai cơ chế xác thực:
```
Authorization: DPoP <access_token>
DPoP: <dpop_proof_jwt>

Trong đó:
- access_token: JWT với claim xác nhận (cnf) liên kết đến chứng chỉ client
- dpop_proof_jwt: Bằng chứng JWT ký bằng khóa riêng tư tương ứng với chứng chỉ
```

**Bước 4: Xác thực token truy cập**
Proxy thực hiện xác thực token toàn diện:
```
Quy trình xác thực Token:
├── Xác minh chữ ký JWT (sử dụng khóa công khai của issuer)
├── Kiểm tra hạn token (claim exp)
├── Xác thực đối tượng (claim aud)
├── Xác minh issuer (claim iss)
├── Kiểm tra not-before (claim nbf)
└── Trích xuất claim xác nhận (claim cnf)
```

**Bước 5: Xác minh bằng chứng DPoP**
Proxy xác thực JWT bằng chứng DPoP:
```
Xác thực bằng chứng DPoP:
├── Xác minh chữ ký JWT (sử dụng khóa công khai client từ chứng chỉ)
├── Khớp phương thức HTTP (claim htm)
├── Khớp URL đích (claim htu)
├── Kiểm tra timestamp (claim iat, thường <60 giây)
├── Xác minh mã định danh duy nhất (claim jti - ngăn phát lại)
└── Xác nhận khóa công khai (claim jwk khớp với chứng chỉ)
```

**Bước 6: Xác minh ràng buộc chứng chỉ-Token**
Bước bảo mật quan trọng - xác minh ràng buộc mã hóa:
```
Quy trình xác minh ràng buộc:
├── Trích xuất khóa công khai từ chứng chỉ client
├── Trích xuất claim xác nhận (cnf) từ access token
├── So sánh dấu vân tay chứng chỉ với cnf.x5t#S256
├── Xác minh chữ ký bằng chứng DPoP khớp với khóa riêng tư chứng chỉ
└── Đảm bảo tính nhất quán thời gian (tất cả thành phần có timestamps hợp lệ)
```

**Bước 7-8: Giao tiếp dịch vụ Backend**
- Nếu tất cả validations đạt, proxy chuyển tiếp request đến backend service
- Request được làm phong phú với thông tin danh tính đã xác minh và security context
- Backend service xử lý business logic và trả về response

**Bước 9: Phân phối phản hồi**
- Proxy nhận response từ backend và thực hiện kiểm tra bảo mật cuối cùng
- Nhật ký kiểm toán được ghi nhận với đầy đủ security context
- Response được gửi về client qua kênh mTLS đã thiết lập

**Xử lý lỗi:**
- Mỗi bước xác thực không thông qua dẫn đến từ chối yêu cầu trực tiếp
- Thu thập nhật ký lỗi cho giám sát bảo mật
- Giới hạn tốc độ và phát hiện bất thường cho các mẫu đáng ngờ
- Kích hoạt thu hồi chứng chỉ tự động nếu phát hiện bị xâm phạm

#### Techstack

**Proxy mTLS (FastAPI):**
Thành phần cốt lõi được phát triển bằng Python FastAPI với các thư viện chuyên biệt gồm (1) cryptography để xử lý chứng chỉ X.509 và các phép toán mật mã; (2) PyJWT cho việc tạo và xác minh JSON Web Tokens; (3) httpx làm HTTP client bất đồng bộ cho reverse proxy; (4) uvicorn làm máy chủ ASGI hiệu suất cao; và (5) pydantic để validation dữ liệu đầu vào. Middleware tùy chỉnh xử lý (1) trích xuất chứng chỉ client từ TLS handshake; (2) xác thực chuỗi chứng chỉ; (3) kiểm tra tình trạng thu hồi qua CRL/OCSP; và (4) thực hiện liên kết mật mã giữa chứng chỉ và token.

**Dịch vụ xác thực:**
Được xây dựng trên FastAPI với Redis làm session store, sử dụng thư viện python-jose để tạo JWT với các claim xác nhận (cnf) liên kết đến dấu vân tay chứng chỉ client. Hỗ trợ nhiều thuật toán ký gồm (1) ECDSA P-256 cho hiệu suất cao; (2) RSA-2048 cho tương thích rộng rãi; và (3) Ed25519 cho bảo mật tối ưu và tốc độ nhanh.

**Các thành phần hỗ trợ:**
Agent cấp chứng chỉ (CA) được thiết lập bằng OpenSSL hoặc CFSSL để tạo Root CA và Intermediate CA với khả năng tạo chứng chỉ đa thuật toán. Quản lý vòng đời chứng chỉ được tự động hóa thông qua scripts Python tích hợp với AWS Secrets Manager. Các dịch vụ backend được phát triển trên FastAPI với SQLAlchemy ORM cho PostgreSQL và redis-py để tương tác với ElastiCache.

### 3.2 Analysis of Proposed Architecture

#### Ưu điểm của kiến trúc

**Enhanced Security:**
1. **Multi-layered Authentication**: Kết hợp xác thực dựa trên chứng chỉ và xác thực dựa trên token
2. **Cryptographic Binding**: Token được ràng buộc với chứng chỉ thông qua các claim cnf
3. **Replay Attack Prevention**: Bằng chứng DPoP bao gồm dấu thời gian, nonce, và dữ liệu cụ thể theo yêu cầu
4. **Reduced Token Theft Impact**: Token bị đánh cắp không thể sử dụng mà không có khóa riêng tư tương ứng

**Operational Benefits:**
1. **Centralized Policy Enforcement**: Tại lớp proxy
2. **Kiến trúc có khả năng mở rộng**: Nhóm **Auto Scaling** và triển khai **Multi-AZ**
3. **Cloud-native Integration**: Tận dụng các dịch vụ được quản lý của AWS
4. **Giám sát toàn diện**: Tích hợp **CloudWatch**, **X-Ray**

#### Thách thức và hạn chế

**Chi phí phụ về hiệu suất:**
- Các tính toán mã hóa bổ sung
- Độ trễ xác thực chứng chỉ
- Thời gian tạo và xác minh bằng chứng DPoP

**Operational Complexity:**
- Quản lý cơ sở hạ tầng PKI
- Tự động hóa vòng đời chứng chỉ
- Quy trình xoay khóa

**Client Implementation:**
- Hỗ trợ thư viện cho DPoP
- Yêu cầu lưu trữ khóa an toàn
- Quy trình đăng ký chứng chỉ

### 3.3 Đánh giá

Phần đánh giá sẽ tập trung vào ba câu hỏi nghiên cứu chính:

#### **RQ1: Security Effectiveness Analysis**

*"Kết hợp mTLS và PoP dựa trên token có giảm đáng kể nguy cơ đánh cắp token/phát lại so với chỉ dùng JWT mang + TLS không?"*

**Phương pháp đánh giá:**

1. **Threat Modeling:**
   - Định nghĩa các attack vectors chính
   - So sánh attack success probability
   - Phân tích blast radius khi compromise

2. **Security Testing:**
   - Mô phỏng đánh cắp token
   - Replay attack testing  
   - Kiểm tra tấn công trung gian
   - Thử nghiệm bỏ qua xác thực chứng chỉ

3. **Comparative Analysis:**
   ```
   Kịch bản kiểm tra:
   ├── JWT mang + TLS (cơ sở)
   ├── chỉ mTLS
   ├── JWT mang + mTLS  
   └── mTLS + DPoP (đề xuất)
   
   Véc-tơ tấn công:
   ├── Đánh cắp token dựa trên XSS
   ├── Chặn bắt mạng
   ├── Xâm phạm điểm cuối
   ├── Tấn công phát lại
   └── Giả mạo chứng chỉ
   ```

**Kỳ vọng kết quả:**
- Giảm 90%+ khả năng đánh cắp token thành công
- Loại bỏ hoàn toàn tấn công phát lại với bằng chứng DPoP mới
- Tăng yêu cầu nỗ lực cho kẻ tấn công từ 1x lên 10x+

#### **RQ2: Đánh giá tác động hiệu suất**

*"Chi phí phụ (độ trễ, thông lượng) của việc kiểm tra mTLS + ràng buộc token ở proxy là bao nhiêu, và có thể tối ưu bằng bộ nhớ đệm/xác minh biên không?"*

**Phương pháp đo lường:**

1. **Benchmark Setup:**
   ```
   Test Environment:
   ├── EC2 t3a.small instances (2 vCPU, 2GB RAM) - Proxy
   ├── EC2 t3a.micro instances (2 vCPU, 1GB RAM) - Backend services
   ├── Application Load Balancer (basic configuration)
   ├── RDS PostgreSQL (db.t3.micro, single AZ)
   ├── ElastiCache Redis (cache.t3.micro, single node)
   └── CloudWatch monitoring (basic metrics)
   
   Test Parameters:
   ├── Concurrent users: 10, 50, 100, 200 
   ├── Mẫu yêu cầu: bền vững, bùng nổ
   ├── Thuật toán chứng chỉ: ECDSA P-256, RSA-2048, Ed25519
   └── Thuật toán token: ES256, RS256, EdDSA
   ```

2. **Số liệu hiệu suất:**
   ```
   Đo lường độ trễ:
   ├── Thời gian bắt tay TLS
   ├── Thời gian xác thực chứng chỉ
   ├── Thời gian xác minh token
   ├── Thời gian xác thực bằng chứng DPoP
   └── Độ trễ yêu cầu đầu cuối
   
   Đo lường thông lượng:
   ├── Yêu cầu mỗi giây (RPS)
   ├── Khả năng kết nối đồng thời
   └── Sử dụng tài nguyên (CPU, Bộ nhớ, Mạng)
   ```

3. **Optimization Testing:**
   ```
   Chiến lược tối ưu hóa:
   ├── Bộ nhớ đệm xác thực chứng chỉ
   ├── Bộ nhớ đệm kết quả xác minh token (dựa trên Redis)
   ├── Lựa chọn thuật toán (Ed25519 được ưu tiên cho hiệu quả tài nguyên)
   ├── Gom nhóm requests (giảm chi phí phụ mỗi yêu cầu)
   ├── Quản lý bộ nhớ (điều chỉnh thu gom rác)
   
   Resource Constraints Considerations:
   ├── Memory: Giới hạn số kết nối đồng thời.
   ├── CPU: Ưu tiên Ed25519, đệm kết quả xác thực
   ├── Mạng: Gộp requests, tối ưu hóa duy trì kết nối
   └── Lưu trữ: Sử dụng bộ nhớ in-memory để đệm, giảm thiểu disk I/O
   ```

**Kỳ vọng kết quả:**
- Base overhead: 40-60ms per request
- Tối ưu vận hành: giảm độ trễ xuống 20% (với caching).
- Throughput: 200-300 RPS (t3a.small), 100-200 RPS (t3a.micro)
- Resource utilization: CPU 60-80%, Memory 50-80% under moderate load

#### **RQ3: Đánh giá chiến lược hoạt động**

*"Chiến lược vận hành (CA, cert rotation, PKI automation) nào cân bằng tốt nhất giữa an toàn và vận hành đơn giản cho môi trường cloud?"*

**Phương pháp đánh giá:**

1. **So sánh chiến lược PKI:**
   ```
   Các chiến lược được đánh giá:
   ├── AWS Private CA + ACM
   └── Public CA (Let's Encrypt, DigiCert)
   
   Tiêu chí đánh giá:
   ├── Độ phức tạp thiết lập (thang điểm 1-10)
   ├── Phân tích chi phí ($/tháng)
   ├── Khả năng tự động hóa
   └── Sẵn sàng khôi phục thảm họa
   ```

2. **Quản lý vòng đời chứng chỉ:**
   ```
   Kịch bản kiểm tra:
   ├── Tự động hóa cấp phát chứng chỉ
   ├── Quy trình xoay vòng (chu kỳ 30, 60, 90 ngày)
   ├── Thu hồi khẩn cấp
   ├── Quản lý chứng chỉ hàng loạt
   ```

3. **Đánh giá tự động hóa:**
   ```
   Mức độ tự động hóa:
   ├── Tự động hoàn toàn (giao thức ACME)
   ├── Bán tự động (Terraform + quy trình phê duyệt)
   ├── Thủ công với công cụ hỗ trợ 
   └── Quy trình hoàn toàn thủ công
   
   Tiêu chí đánh giá:
   ├── Thời gian trung bình cấp phát chứng chỉ (MTTCI)
   ├── Sự cố hết hạn chứng chỉ
   ├── Chi phí vận hành mỗi chứng chỉ
   ```

**Kỳ vọng kết quả:**
- **AWS Private CA** + xoay vòng tự động: giảm chi phí phụ vận hành
- **Infrastructure-as-Code**: 70% giảm lỗi cấu hình
- Tích hợp giao thức **ACME**: 95% tỷ lệ tự động hóa

#### **Phân tích so sánh thuật toán**

Một phần quan trọng của đánh giá là so sánh hiệu suất các thuật toán mã hóa:

```
Ma trận hiệu suất thuật toán (trên **t3a.micro/small**):

                 ECDSA P-256    RSA-2048      Ed25519
Certificate Gen    ?ms          ?ms           ?ms
Cert Validation    ?ms          ?ms           ?ms  
Token Signing      ?ms          ?ms           ?ms
Token Verify       ?ms          ?ms           ?ms
Memory Usage       ?            ?             ?
CPU Usage          ?            ?             ?
Key Size          256-bit       2048-bit      255-bit
Security Level    ~128-bit      ~112-bit      ~128-bit
```

#### **Triển khai demo**

Để xác thực các phát hiện, sẽ xây dựng một ứng dụng demo mô phỏng giao tiếp giữa client và server trong hệ thống micro-services:

**Kiến trúc demo micro-services:**
```
Kịch bản demo:
├── Client application xác thực qua mTLS
├── API Gateway proxy với xác thực Zero-Trust
├── Service-to-service communication với DPoP tokens
├── User Service (quản lý danh tính người dùng)
├── Product Service (quản lý sản phẩm)
├── Giám sát hiệu suất thời gian thực
└── Minh họa sự kiện bảo mật
```

**Trực quan hóa hiệu suất:**
- Biểu đồ độ trễ thời gian thực
- Biểu đồ so sánh thông lượng
- Giám sát sử dụng tài nguyên
- Tương quan sự kiện bảo mật
- Bảng điều khiển phân tích chi phí

## 4. Kết luận

Nghiên cứu này đề xuất một kiến trúc Zero-Trust API authentication kết hợp mTLS và token-based signatures nhằm tăng cường bảo mật cho API trong môi trường cloud. Kiến trúc được thiết kế để giải quyết các hạn chế của bearer tokens truyền thống thông qua việc tạo ra cryptographic binding giữa client certificates và access tokens.

### Đóng góp chính:

1. **Kiến trúc tích hợp**: Kết hợp mTLS với DPoP tokens tạo ra multi-layered authentication với strong cryptographic binding

2. **Phân tích hiệu suất**: So sánh toàn diện các thuật toán mã hóa (**ECDSA**, **RSA**, **Ed25519**) trong môi trường sản xuất

3. **Operational strategies**: Đề xuất các chiến lược PKI automation phù hợp với cloud-native environments

4. **Implementation roadmap**: Cung cấp hướng dẫn chi tiết để triển khai trên AWS với Terraform

### Kỳ vọng về tác động:

**Về mặt bảo mật:**
- Giảm đáng kể nguy cơ đánh cắp token và tấn công phát lại
- Tăng effort requirement cho attackers
- Cung cấp nhật ký kiểm toán toàn diện

**Về mặt hiệu suất:**
- Xác định overhead chính xác của enhanced security measures
- Đề xuất optimization strategies hiệu quả
- Cân bằng giữa bảo mật và hiệu suất

**Về mặt vận hành:**
- Quản lý PKI dễ dàng thông qua cloud services
- Quản lý vòng đời chứng chỉ tự động
- Làm giảm operational overhead và human errors

### Nghiên cứu tương lai:

1. **Post-quantum cryptography**: Tích hợp các thuật toán quantum-resistant
2. **Edge computing**: Mở rộng model cho edge/IoT environments  
3. **Machine learning**: Sử dụng ML cho anomaly detection và adaptive authentication
4. **Cross-cloud integration**: Multi-cloud PKI federation và trust models

Nghiên cứu này sẽ cung cấp nền tảng vững chắc cho việc triển khai bảo mật API Zero-Trust trong môi trường sản xuất, với trọng tâm đặc biệt vào các cân nhắc thực tế như hiệu suất, vận hành, và tối ưu hóa chi phí.

## 5. Tài liệu tham khảo

[1] RFC 7800: Proof-of-Possession Key Semantics for JSON Web Tokens (JWT), IETF, 2016  
    https://tools.ietf.org/rfc/rfc7800.txt

[2] RFC 9449: OAuth 2.0 Demonstrating Proof-of-Possession at the Application Layer (DPoP), IETF, 2023  
    https://tools.ietf.org/rfc/rfc9449.txt

[3] RFC 8705: OAuth 2.0 Mutual-TLS Client Authentication and Certificate-Bound Access Tokens, IETF, 2020  
    https://tools.ietf.org/rfc/rfc8705.txt

[4] NIST SP 800-207: Zero Trust Architecture, NIST, 2020  
    https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-207.pdf

[5] Ward, R., & Beyer, B. "BeyondCorp: A New Approach to Enterprise Security", USENIX, 2014  
    https://www.usenix.org/conference/lisa14/conference-program/presentation/ward

[6] Microsoft Zero Trust Security Model, Microsoft Documentation, 2021  
    https://docs.microsoft.com/en-us/security/zero-trust/

[7] EU Payment Services Directive 2 (PSD2), European Parliament, 2015  
    https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=celex%3A32015L2366

[8] Financial-grade API Security Profile 1.0, OpenID Foundation, 2021  
    https://openid.net/specs/openid-financial-api-part-1-1_0.html

[9] Open Banking Implementation Entity, "Open Banking Security Profile", 2020  
    https://standards.openbanking.org.uk/security-profiles/

[10] SWIFT Customer Security Programme (CSP), SWIFT, 2022  
     https://www.swift.com/myswift/customer-security-programme-csp

[11] Istio Service Mesh Documentation, Google/IBM/Lyft, 2023  
     https://istio.io/latest/docs/

[12] Zuul Gateway, Netflix OSS, GitHub Repository, 2023  
     https://github.com/Netflix/zuul

[13] "Scaling Uber's Identity Platform", Uber Engineering Blog, 2019  
     https://eng.uber.com/scaling-ubers-identity-platform/

[14] "Mobile API Security at Spotify", Spotify Engineering Blog, 2020  
     https://engineering.atspotify.com/2020/02/mobile-api-security/

[15] Kong Gateway Documentation, Kong Inc., 2023  
     https://docs.konghq.com/gateway/

[16] Istio Security Best Practices, Istio Documentation, 2023  
     https://istio.io/latest/docs/ops/best-practices/security/

[17] AWS API Gateway Developer Guide, Amazon Web Services, 2023  
     https://docs.aws.amazon.com/apigateway/

[18] Envoy Proxy Documentation, CNCF, 2023  
     https://www.envoyproxy.io/docs/envoy/latest/