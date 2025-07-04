import { Component, signal, computed } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { startRegistration, startAuthentication } from '@simplewebauthn/browser';

interface LogEntry {
  timestamp: string;
  type: 'request' | 'response' | 'client-generated' | 'ctap2' | 'error';
  operation: 'registration' | 'authentication';
  step: string;
  data: any;
  url?: string;
  decoded?: boolean;
  decodedData?: any;
}

@Component({
  selector: 'app-root',
  imports: [CommonModule, FormsModule],
  templateUrl: './app.html',
  styleUrl: './app.css'
})
export class App {
  username = signal('');
  isLoading = signal(false);
  logs = signal<LogEntry[]>([]);
  accessToken = signal<string | null>(null);
  
  private baseUrl = 'http://localhost:3000';

  constructor(private http: HttpClient) {}

  private addLog(entry: Omit<LogEntry, 'timestamp'>) {
    this.logs.update(logs => [...logs, {
      ...entry,
      timestamp: new Date().toISOString(),
      decoded: false
    }]);
  }

  clearLogs() {
    this.logs.set([]);
    this.accessToken.set(null);
  }

  async verifyToken() {
    const token = this.accessToken();
    if (!token) {
      return;
    }

    this.isLoading.set(true);

    try {
      this.addLog({
        type: 'request',
        operation: 'authentication',
        step: 'Verifying access token',
        data: { 
          token: token,
          authorizationHeader: `Bearer ${token}`
        },
        url: `${this.baseUrl}/verify`
      });

      const response = await this.http.get<any>(`${this.baseUrl}/verify`, {
        headers: {
          'Authorization': `Bearer ${token}`
        }
      }).toPromise();

      this.addLog({
        type: 'response',
        operation: 'authentication',
        step: 'Token verification result',
        data: response,
        url: `${this.baseUrl}/verify`
      });

    } catch (error) {
      this.addLog({
        type: 'error',
        operation: 'authentication',
        step: 'Token verification failed',
        data: error
      });
    } finally {
      this.isLoading.set(false);
    }
  }

  async registerPasskey() {
    if (!this.username().trim()) {
      alert('Please enter a username');
      return;
    }

    this.isLoading.set(true);
    
    try {
      this.addLog({
        type: 'request',
        operation: 'registration',
        step: 'Getting attestation options',
        data: { username: this.username() },
        url: `${this.baseUrl}/attestation/option`
      });

      const optionsResponse = await this.http.post<any>(`${this.baseUrl}/attestation/option`, { 
        username: this.username() 
      }).toPromise();

      this.addLog({
        type: 'response',
        operation: 'registration',
        step: 'Received attestation options',
        data: optionsResponse,
        url: `${this.baseUrl}/attestation/option`
      });

      // Create a clientDataJSON based on the challenge from options
      const clientDataJSON = {
        type: 'webauthn.create',
        challenge: optionsResponse.challenge || 'challenge-from-server',
        origin: window.location.origin,
        crossOrigin: false
      };

      // Calculate clientDataHash for display
      const clientDataStr = JSON.stringify(clientDataJSON);
      const clientDataHashPromise = this.calculateSHA256(clientDataStr);

      this.addLog({
        type: 'ctap2',
        operation: 'registration',
        step: 'CTAP2 Request: authenticatorMakeCredential (0x01)',
        data: {
          command: 'authenticatorMakeCredential',
          commandCode: '0x01',
          hexData: '0x01',
          description: 'Request to create a new credential',
          actualData: {
            clientDataHash: 'Calculating...',
            rp: optionsResponse.rp || { id: 'localhost', name: 'Passkey Demo' },
            user: optionsResponse.user || { id: 'Generated', name: this.username() },
            pubKeyCredParams: optionsResponse.pubKeyCredParams || [{ type: 'public-key', alg: -7 }]
          },
          decodedData: {
            clientDataJSON: clientDataJSON,
            rp: optionsResponse.rp || { id: 'localhost', name: 'Passkey Demo' },
            user: optionsResponse.user || { id: 'Generated', name: this.username() },
            pubKeyCredParams: optionsResponse.pubKeyCredParams || [{ type: 'public-key', alg: -7 }]
          }
        }
      });

      // Update the hash when calculated
      clientDataHashPromise.then(hash => {
        this.updateCTAP2LogClientDataHash('authenticatorMakeCredential', hash);
      });

      const credential = await startRegistration(optionsResponse);

      this.addLog({
        type: 'ctap2',
        operation: 'registration',
        step: 'CTAP2 Response: Attestation (0x01)',
        data: {
          response: 'Attestation',
          responseCode: '0x01',
          hexData: '0x00',
          description: 'Attestation response from authenticator',
          actualData: {
            fmt: 'packed',
            authData: 'Binary data (contained in attestationObject)',
            attStmt: 'CBOR data (contained in attestationObject)',
            attestationObject: credential.response?.attestationObject || 'N/A'
          },
          decodedData: {
            fmt: 'packed (typical format)',
            authData: 'RP ID hash + flags + counter + attested credential data',
            attStmt: 'Format-specific attestation statement',
            attestationObjectDecoded: {
              note: 'CBOR-encoded object containing authData, fmt, and attStmt',
              credentialId: credential.id || 'Generated credential ID'
            }
          }
        }
      });

      this.addLog({
        type: 'client-generated',
        operation: 'registration',
        step: 'Generated credential',
        data: credential
      });

      this.addLog({
        type: 'request',
        operation: 'registration',
        step: 'Sending attestation result',
        data: { credential, username: this.username() },
        url: `${this.baseUrl}/attestation/result`
      });

      const verificationResponse = await this.http.post<any>(`${this.baseUrl}/attestation/result`, { 
        credential, 
        username: this.username() 
      }).toPromise();

      this.addLog({
        type: 'response',
        operation: 'registration',
        step: 'Received verification result',
        data: verificationResponse,
        url: `${this.baseUrl}/attestation/result`
      });

      if (verificationResponse?.verified) {
        this.addLog({
          type: 'client-generated',
          operation: 'registration',
          step: 'Registration successful',
          data: { success: true }
        });
      }

    } catch (error) {
      this.addLog({
        type: 'error',
        operation: 'registration',
        step: 'Registration failed',
        data: error
      });
    } finally {
      this.isLoading.set(false);
    }
  }

  async authenticatePasskey() {
    if (!this.username().trim()) {
      alert('Please enter a username');
      return;
    }

    this.isLoading.set(true);
    
    try {
      this.addLog({
        type: 'request',
        operation: 'authentication',
        step: 'Getting assertion options',
        data: { username: this.username() },
        url: `${this.baseUrl}/assertion/option`
      });

      const optionsResponse = await this.http.post<any>(`${this.baseUrl}/assertion/option`, { 
        username: this.username() 
      }).toPromise();

      this.addLog({
        type: 'response',
        operation: 'authentication',
        step: 'Received assertion options',
        data: optionsResponse,
        url: `${this.baseUrl}/assertion/option`
      });

      // Create a clientDataJSON based on the challenge from options
      const clientDataJSON = {
        type: 'webauthn.get',
        challenge: optionsResponse.challenge || 'challenge-from-server',
        origin: window.location.origin,
        crossOrigin: false
      };

      // Calculate clientDataHash for display
      const clientDataStr = JSON.stringify(clientDataJSON);
      const clientDataHashPromise = this.calculateSHA256(clientDataStr);

      this.addLog({
        type: 'ctap2',
        operation: 'authentication',
        step: 'CTAP2 Request: authenticatorGetAssertion (0x02)',
        data: {
          command: 'authenticatorGetAssertion',
          commandCode: '0x02',
          hexData: '0x02',
          description: 'Request to get an assertion from existing credential',
          actualData: {
            rpId: optionsResponse.rpId || 'localhost',
            clientDataHash: 'Calculating...',
            allowList: optionsResponse.allowCredentials || [],
            options: {
              up: true,
              uv: optionsResponse.userVerification || 'preferred'
            }
          },
          decodedData: {
            rpId: optionsResponse.rpId || 'localhost',
            clientDataJSON: clientDataJSON,
            allowList: optionsResponse.allowCredentials || [],
            options: {
              up: true,
              uv: optionsResponse.userVerification || 'preferred'
            }
          }
        }
      });

      // Update the hash when calculated
      clientDataHashPromise.then(hash => {
        this.updateCTAP2LogClientDataHash('authenticatorGetAssertion', hash);
      });

      const credential = await startAuthentication(optionsResponse);

      this.addLog({
        type: 'ctap2',
        operation: 'authentication',
        step: 'CTAP2 Response: Assertion (0x02)',
        data: {
          response: 'Assertion',
          responseCode: '0x02',
          hexData: '0x00',
          description: 'Assertion response from authenticator',
          actualData: {
            credentialId: credential.id || 'Selected credential ID',
            authData: credential.response?.authenticatorData || 'N/A',
            signature: credential.response?.signature || 'N/A',
            userHandle: credential.response?.userHandle || null
          },
          decodedData: {
            credentialId: 'Selected credential identifier',
            authData: 'RP ID hash + flags + signature counter',
            signature: 'Digital signature over authData + clientDataHash',
            userHandle: 'User identifier (if resident key)'
          }
        }
      });

      this.addLog({
        type: 'client-generated',
        operation: 'authentication',
        step: 'Generated assertion',
        data: credential
      });

      this.addLog({
        type: 'request',
        operation: 'authentication',
        step: 'Sending assertion result',
        data: { credential, username: this.username() },
        url: `${this.baseUrl}/assertion/result`
      });

      const verificationResponse = await this.http.post<any>(`${this.baseUrl}/assertion/result`, { 
        credential, 
        username: this.username() 
      }).toPromise();

      this.addLog({
        type: 'response',
        operation: 'authentication',
        step: 'Received verification result',
        data: verificationResponse,
        url: `${this.baseUrl}/assertion/result`
      });

      if (verificationResponse?.verified) {
        // Store access token if available
        if (verificationResponse.accessToken) {
          this.accessToken.set(verificationResponse.accessToken);
        }
      }

    } catch (error) {
      this.addLog({
        type: 'error',
        operation: 'authentication',
        step: 'Authentication failed',
        data: error
      });
    } finally {
      this.isLoading.set(false);
    }
  }

  getLogTypeClass(type: string): string {
    switch (type) {
      case 'request': return 'log-request';
      case 'response': return 'log-response';
      case 'client-generated': return 'log-client';
      case 'ctap2': return 'log-ctap2';
      case 'error': return 'log-error';
      default: return '';
    }
  }

  formatJson(data: any): string {
    return JSON.stringify(data, null, 2);
  }

  toggleDecoded(logIndex: number) {
    this.logs.update(logs => {
      const updatedLogs = [...logs];
      const log = updatedLogs[logIndex];
      
      if (!log.decoded) {
        // Decode the data
        const decodedData = this.decodeWebAuthnData(log.data);
        updatedLogs[logIndex] = {
          ...log,
          decoded: true,
          decodedData
        };
      } else {
        // Switch back to original
        updatedLogs[logIndex] = {
          ...log,
          decoded: false
        };
      }
      
      return updatedLogs;
    });
  }

  private decodeWebAuthnData(data: any): any {
    if (!data || typeof data !== 'object') return data;
    
    // Handle CTAP2 command data
    if (data.command || data.response) {
      return this.decodeCTAP2Data(data);
    }
    
    // Create decoded object preserving key order
    const decoded: any = {};
    
    // Copy all keys in original order, replacing specific nested objects
    Object.keys(data).forEach(key => {
      if (key === 'credential' && data.credential?.response) {
        decoded.credential = { ...data.credential };
        decoded.credential.response = this.createOrderedDecodedResponse(data.credential.response);
      } else if (key === 'response' && !data.credential) {
        decoded.response = this.createOrderedDecodedResponse(data.response);
      } else {
        decoded[key] = data[key];
      }
    });
    
    return decoded;
  }

  private createOrderedDecodedResponse(response: any): any {
    const decodedResponse: any = {};
    
    // Process keys in original order
    Object.keys(response).forEach(key => {
      if (key === 'clientDataJSON' && response[key]) {
        try {
          const clientDataStr = atob(response[key]);
          decodedResponse[key] = JSON.parse(clientDataStr);
        } catch (e) {
          decodedResponse[key] = 'Failed to decode clientDataJSON';
        }
      } else if (key === 'attestationObject' && response[key]) {
        decodedResponse[key] = {
          note: 'CBOR-encoded object containing authData, fmt, and attStmt',
          raw: response[key]
        };
      } else if (key === 'authenticatorData' && response[key]) {
        decodedResponse[key] = {
          note: 'Binary data containing RP ID hash, flags, counter, and extensions',
          raw: response[key]
        };
      } else if (key === 'signature' && response[key]) {
        decodedResponse[key] = {
          note: 'Digital signature over authenticatorData and clientDataHash',
          raw: response[key]
        };
      } else {
        decodedResponse[key] = response[key];
      }
    });
    
    return decodedResponse;
  }


  private async calculateSHA256(text: string): Promise<string> {
    const encoder = new TextEncoder();
    const data = encoder.encode(text);
    const hashBuffer = await crypto.subtle.digest('SHA-256', data);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
  }

  private updateCTAP2LogClientDataHash(command: string, hash: string): void {
    this.logs.update(logs => {
      return logs.map(log => {
        if (log.type === 'ctap2' && log.data.command === command && log.data.actualData) {
          // Update the actualData with calculated hash
          const updatedData = { ...log.data };
          updatedData.actualData = { ...log.data.actualData, clientDataHash: hash };
          return { ...log, data: updatedData };
        }
        return log;
      });
    });
  }

  private decodeCTAP2Data(data: any): any {
    // For CTAP2 data, create a completely new structure for decoded view
    if (data.decodedData) {
      const decoded: any = {
        command: data.command,
        commandCode: data.commandCode,
        response: data.response,
        responseCode: data.responseCode,
        hexData: data.hexData,
        description: data.description
      };
      
      // For attestation response, replace attestationObject with attestationObjectDecoded
      if (data.response === 'Attestation' && data.decodedData.attestationObjectDecoded) {
        decoded.actualData = {
          fmt: data.decodedData.fmt,
          authData: data.decodedData.authData,
          attStmt: data.decodedData.attStmt,
          attestationObjectDecoded: data.decodedData.attestationObjectDecoded
        };
      } else {
        // For other cases, use decodedData as actualData
        decoded.actualData = { ...data.decodedData };
      }
      
      return decoded;
    }
    
    return data;
  }

  shouldShowDecodeButton(log: LogEntry): boolean {
    // Show decode button for client-generated data with WebAuthn responses
    if (log.type === 'client-generated' && 
        log.data && 
        log.data.response && 
        (log.data.response.clientDataJSON || log.data.response.attestationObject)) {
      return true;
    }
    
    // Show decode button for request data containing credentials
    if (log.type === 'request' && 
        log.data && 
        log.data.credential &&
        log.data.credential.response &&
        (log.data.credential.response.clientDataJSON || log.data.credential.response.attestationObject)) {
      return true;
    }
    
    // Show decode button for CTAP2 commands with decodedData
    if (log.type === 'ctap2' && 
        log.data && 
        log.data.decodedData) {
      return true;
    }
    
    return false;
  }

  getDisplayData(log: LogEntry): any {
    if (log.decoded && log.decodedData) {
      return log.decodedData;
    }
    
    // For non-decoded CTAP2 logs, hide decodedData from display
    if (log.type === 'ctap2' && log.data && log.data.decodedData && !log.decoded) {
      const displayData = { ...log.data };
      delete displayData.decodedData;
      return displayData;
    }
    
    return log.data;
  }
}
