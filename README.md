# Spring Boot Keycloak-Demo-Anwendungen

## Über die Projekte
Dieses Repository enthält zwei Demo-Anwendungen, die die Implementierung von OAuth 2.0 Flows unter Verwendung von Keycloak in Spring Boot demonstrieren:
- **Authorization Code Flow**
- **Resource Owner Password Credentials Grant**

Beide Projekte zielen darauf ab, Entwicklern praktische Leitfäden zu bieten, um sichere Authentifizierungsmechanismen in ihren eigenen Projekten zu implementieren.

## Authorization Code Flow
Wechsle in das Verzeichnis mit `cd zeus-keycloak-demo/authorization-code-flow`. Dieses Projekt demonstriert die Implementierung des Standard-Authentifizierungsflusses von Keycloak, der auf dem OAuth 2.0 Authorization Code Flow basiert.

## Resource Owner Password Credentials Grant
Wechsle in das Verzeichnis mit `cd zeus-keycloak-demo/resource-owner-password-credentials-grant`. Dieses Projekt zeigt die Implementierung des Resource Owner Password Credentials Grant Flows.

## Voraussetzungen
- Java 17
- Maven
- Keycloak Server (lokal oder remote)

## Installation und Setup
1. Repository klonen: `git clone https://github.com/gzeuner/zeus-keycloak-demo.git`
2. Zum gewünschten Projektverzeichnis navigieren.
3. Anwendung mit Maven starten: `mvn spring-boot:run`
4. Die Anwendung ist unter `http://localhost:8081` erreichbar.

## Konfiguration
Informationen zur Verbindung und Konfiguration der Anwendung mit einem Keycloak-Server (z.B. Keycloak-Server-URL, Client-IDs, Geheimnisse usw.).

## Lizenz
Dieses Projekt steht unter der Apache License 2.0. Weitere Informationen finden Sie in der [LICENSE](LICENSE)-Datei.

## Haftungsausschluss
Dieser Code wird in der vorliegenden Form ohne jegliche Garantie zu Trainingszwecken zur Verfügung gestellt.

## Weitere Ressourcen
Besuchen Sie [tiny-tool.de](https://www.tiny-tool.de) für weitere nützliche Entwicklertools und Ressourcen.

---

# Spring Boot Keycloak Demo Applications

## About the Projects
This repository contains two demo applications demonstrating the implementation of OAuth 2.0 Flows using Keycloak in Spring Boot:
- **Authorization Code Flow**
- **Resource Owner Password Credentials Grant**

Both projects aim to provide developers with practical guides to implement secure authentication mechanisms in their own projects.

## Authorization Code Flow
Switch to the directory with `cd zeus-keycloak-demo/authorization-code-flow`. This project demonstrates the implementation of Keycloak's standard authentication flow based on the OAuth 2.0 Authorization Code Flow.

## Resource Owner Password Credentials Grant
Switch to the directory with `cd zeus-keycloak-demo/resource-owner-password-credentials-grant`. This project illustrates the implementation of the Resource Owner Password Credentials Grant Flow.

## Prerequisites
- Java 17
- Maven
- Keycloak Server (local or remote)

## Installation and Setup
1. Clone the repository: `git clone https://github.com/gzeuner/zeus-keycloak-demo.git`
2. Navigate to the desired project directory.
3. Start the application with Maven: `mvn spring-boot:run`
4. The application is accessible at `http://localhost:8081`.

## Configuration
Information on connecting and configuring the application with a Keycloak server (e.g., Keycloak server URL, client IDs, secrets, etc.).

## License
This project is under the Apache License 2.0. For more information, see the [LICENSE](LICENSE) file.

## Discclaimer
This code is provided in its present form without any guarantee for training purposes.

## Authors and Acknowledgements
Visit https://www.tiny-tool.de
