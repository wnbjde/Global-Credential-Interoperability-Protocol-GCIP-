 
import { describe, it, expect, beforeEach } from "vitest";
import {
	stringUtf8CV,
	uintCV,
	buffCV,
	principalCV,
} from "@stacks/transactions";

const ERR_NOT_AUTHORIZED = 100;
const ERR_INVALID_CREDENTIAL = 101;
const ERR_REVOKED = 102;
const ERR_INVALID_ISSUER = 103;
const ERR_INVALID_HASH = 104;
const ERR_INVALID_FEE = 105;
const ERR_VERIFICATION_FAILED = 106;
const ERR_CREDENTIAL_EXPIRED = 107;
const ERR_INVALID_EXPIRATION = 108;
const ERR_INVALID_SIGNATURE = 109;
const ERR_AUDIT_LOG_FAIL = 110;
const ERR_INVALID_VERIFIER = 111;
const ERR_FEE_TRANSFER_FAIL = 112;
const ERR_INVALID_BATCH_SIZE = 113;
const ERR_BATCH_VERIFICATION_FAIL = 114;
const ERR_INVALID_CREDENTIAL_TYPE = 115;
const ERR_INVALID_STATUS = 116;
const ERR_MAX_VERIFICATIONS_EXCEEDED = 117;
const ERR_INVALID_TIMESTAMP = 118;
const ERR_AUTHORITY_NOT_VERIFIED = 119;
const ERR_INVALID_MIN_FEE = 120;

interface Verification {
	credentialId: number;
	issuer: string;
	hash: Uint8Array;
	verifier: string;
	timestamp: number;
	status: boolean;
	expiration: number;
	signature: Uint8Array;
	credentialType: string;
	feePaid: number;
}

interface Result<T> {
	ok: boolean;
	value: T;
}

class VerificationContractMock {
	state: {
		nextVerificationId: number;
		minVerificationFee: number;
		maxBatchSize: number;
		authorityContract: string | null;
		verificationCount: number;
		maxVerifications: number;
		verifications: Map<number, Verification>;
		verificationByCredential: Map<number, number>;
		batchVerifications: Map<number, number[]>;
	} = {
		nextVerificationId: 0,
		minVerificationFee: 100,
		maxBatchSize: 10,
		authorityContract: null,
		verificationCount: 0,
		maxVerifications: 10000,
		verifications: new Map(),
		verificationByCredential: new Map(),
		batchVerifications: new Map(),
	};
	blockHeight: number = 0;
	caller: string = "ST1TEST";
	stxTransfers: Array<{ amount: number; from: string; to: string | null }> = [];
	mockIssuerData: Map<string, unknown> = new Map();
	mockCredentialData: Map<number, { hash: Uint8Array }> = new Map();
	mockRevocationStatus: Map<number, boolean> = new Map();
	mockAuditLogSuccess: boolean = true;

	constructor() {
		this.reset();
	}

	reset() {
		this.state = {
			nextVerificationId: 0,
			minVerificationFee: 100,
			maxBatchSize: 10,
			authorityContract: null,
			verificationCount: 0,
			maxVerifications: 10000,
			verifications: new Map(),
			verificationByCredential: new Map(),
			batchVerifications: new Map(),
		};
		this.blockHeight = 0;
		this.caller = "ST1TEST";
		this.stxTransfers = [];
		this.mockIssuerData = new Map();
		this.mockCredentialData = new Map();
		this.mockRevocationStatus = new Map();
		this.mockAuditLogSuccess = true;
	}

	setAuthorityContract(contractPrincipal: string): Result<boolean> {
		if (contractPrincipal === "SP000000000000000000002Q6VF78") {
			return { ok: false, value: false };
		}
		if (this.state.authorityContract !== null) {
			return { ok: false, value: false };
		}
		this.state.authorityContract = contractPrincipal;
		return { ok: true, value: true };
	}

	setMinVerificationFee(newFee: number): Result<boolean> {
		if (!this.state.authorityContract) return { ok: false, value: false };
		this.state.minVerificationFee = newFee;
		return { ok: true, value: true };
	}

	setMaxBatchSize(newSize: number): Result<boolean> {
		if (!this.state.authorityContract) return { ok: false, value: false };
		if (newSize <= 0) return { ok: false, value: false };
		this.state.maxBatchSize = newSize;
		return { ok: true, value: true };
	}

	verifyCredential(
		credentialId: number,
		issuer: string,
		credentialHash: Uint8Array,
		expiration: number,
		signature: Uint8Array,
		credentialType: string
	): Result<number> {
		if (credentialId <= 0) return { ok: false, value: ERR_INVALID_CREDENTIAL };
		if (issuer === this.caller) return { ok: false, value: ERR_INVALID_ISSUER };
		if (credentialHash.length !== 32)
			return { ok: false, value: ERR_INVALID_HASH };
		if (expiration <= this.blockHeight)
			return { ok: false, value: ERR_INVALID_EXPIRATION };
		if (signature.length !== 65)
			return { ok: false, value: ERR_INVALID_SIGNATURE };
		if (
			!["education", "certification", "work-history"].includes(credentialType)
		)
			return { ok: false, value: ERR_INVALID_CREDENTIAL_TYPE };
		if (!this.mockIssuerData.has(issuer))
			return { ok: false, value: ERR_INVALID_ISSUER };
		if (!this.mockCredentialData.has(credentialId))
			return { ok: false, value: ERR_INVALID_CREDENTIAL };
		const credData = this.mockCredentialData.get(credentialId)!;
		if (!this.arrayBuffersEqual(credData.hash, credentialHash))
			return { ok: false, value: ERR_INVALID_HASH };
		if (this.mockRevocationStatus.get(credentialId) ?? false)
			return { ok: false, value: ERR_REVOKED };
		if (this.state.verificationCount >= this.state.maxVerifications)
			return { ok: false, value: ERR_MAX_VERIFICATIONS_EXCEEDED };
		if (!this.mockAuditLogSuccess)
			return { ok: false, value: ERR_AUDIT_LOG_FAIL };

		const id = this.state.nextVerificationId;
		const verification: Verification = {
			credentialId,
			issuer,
			hash: credentialHash,
			verifier: this.caller,
			timestamp: this.blockHeight,
			status: true,
			expiration,
			signature,
			credentialType,
			feePaid: 0,
		};
		this.state.verifications.set(id, verification);
		this.state.verificationByCredential.set(credentialId, id);
		this.state.nextVerificationId++;
		this.state.verificationCount++;
		return { ok: true, value: id };
	}

	verifyCredentialWithFee(
		credentialId: number,
		issuer: string,
		credentialHash: Uint8Array,
		expiration: number,
		signature: Uint8Array,
		credentialType: string,
		fee: number
	): Result<number> {
		if (fee < this.state.minVerificationFee)
			return { ok: false, value: ERR_INVALID_FEE };
		if (!this.state.authorityContract)
			return { ok: false, value: ERR_AUTHORITY_NOT_VERIFIED };

		this.stxTransfers.push({
			amount: fee,
			from: this.caller,
			to: this.state.authorityContract,
		});

		const result = this.verifyCredential(
			credentialId,
			issuer,
			credentialHash,
			expiration,
			signature,
			credentialType
		);
		if (!result.ok) return result;
		const id = result.value as number;
		const verification = this.state.verifications.get(id)!;
		this.state.verifications.set(id, { ...verification, feePaid: fee });
		return { ok: true, value: id };
	}

	batchVerifyCredentials(
		credentials: Array<{
			credId: number;
			issuer: string;
			hash: Uint8Array;
			exp: number;
			sig: Uint8Array;
			type: string;
		}>
	): Result<number> {
		const len = credentials.length;
		if (len <= 0 || len > this.state.maxBatchSize)
			return { ok: false, value: ERR_INVALID_BATCH_SIZE };

		const batchId = this.state.nextVerificationId;
		const results: number[] = [];
		for (const item of credentials) {
			const res = this.verifyCredential(
				item.credId,
				item.issuer,
				item.hash,
				item.exp,
				item.sig,
				item.type
			);
			if (!res.ok) return { ok: false, value: ERR_BATCH_VERIFICATION_FAIL };
			results.push(res.value as number);
		}
		this.state.batchVerifications.set(batchId, results);
		this.state.nextVerificationId++;
		return { ok: true, value: batchId };
	}

	getVerification(id: number): Verification | null {
		return this.state.verifications.get(id) || null;
	}

	getVerificationCount(): Result<number> {
		return { ok: true, value: this.state.verificationCount };
	}

	checkCredentialVerified(credId: number): Result<boolean> {
		return { ok: true, value: this.state.verificationByCredential.has(credId) };
	}

	private arrayBuffersEqual(buf1: Uint8Array, buf2: Uint8Array): boolean {
		if (buf1.length !== buf2.length) return false;
		for (let i = 0; i < buf1.length; i++) {
			if (buf1[i] !== buf2[i]) return false;
		}
		return true;
	}
}

describe("VerificationContract", () => {
	let contract: VerificationContractMock;

	beforeEach(() => {
		contract = new VerificationContractMock();
		contract.reset();
	});

	it("verifies a credential successfully", () => {
		contract.setAuthorityContract("ST2TEST");
		contract.mockIssuerData.set("ST3ISSUER", {});
		contract.mockCredentialData.set(1, { hash: new Uint8Array(32).fill(1) });
		contract.mockRevocationStatus.set(1, false);
		const result = contract.verifyCredential(
			1,
			"ST3ISSUER",
			new Uint8Array(32).fill(1),
			100,
			new Uint8Array(65).fill(2),
			"education"
		);
		expect(result.ok).toBe(true);
		expect(result.value).toBe(0);

		const verification = contract.getVerification(0);
		expect(verification?.credentialId).toBe(1);
		expect(verification?.issuer).toBe("ST3ISSUER");
		expect(verification?.verifier).toBe("ST1TEST");
		expect(verification?.status).toBe(true);
		expect(verification?.expiration).toBe(100);
		expect(verification?.credentialType).toBe("education");
		expect(verification?.feePaid).toBe(0);
	});

	it("rejects verification with invalid credential ID", () => {
		contract.setAuthorityContract("ST2TEST");
		const result = contract.verifyCredential(
			0,
			"ST3ISSUER",
			new Uint8Array(32).fill(1),
			100,
			new Uint8Array(65).fill(2),
			"education"
		);
		expect(result.ok).toBe(false);
		expect(result.value).toBe(ERR_INVALID_CREDENTIAL);
	});

	it("rejects verification with invalid issuer", () => {
		contract.setAuthorityContract("ST2TEST");
		const result = contract.verifyCredential(
			1,
			"ST1TEST",
			new Uint8Array(32).fill(1),
			100,
			new Uint8Array(65).fill(2),
			"education"
		);
		expect(result.ok).toBe(false);
		expect(result.value).toBe(ERR_INVALID_ISSUER);
	});

	it("rejects verification with mismatched hash", () => {
		contract.setAuthorityContract("ST2TEST");
		contract.mockIssuerData.set("ST3ISSUER", {});
		contract.mockCredentialData.set(1, { hash: new Uint8Array(32).fill(1) });
		const result = contract.verifyCredential(
			1,
			"ST3ISSUER",
			new Uint8Array(32).fill(3),
			100,
			new Uint8Array(65).fill(2),
			"education"
		);
		expect(result.ok).toBe(false);
		expect(result.value).toBe(ERR_INVALID_HASH);
	});

	it("rejects verification if revoked", () => {
		contract.setAuthorityContract("ST2TEST");
		contract.mockIssuerData.set("ST3ISSUER", {});
		contract.mockCredentialData.set(1, { hash: new Uint8Array(32).fill(1) });
		contract.mockRevocationStatus.set(1, true);
		const result = contract.verifyCredential(
			1,
			"ST3ISSUER",
			new Uint8Array(32).fill(1),
			100,
			new Uint8Array(65).fill(2),
			"education"
		);
		expect(result.ok).toBe(false);
		expect(result.value).toBe(ERR_REVOKED);
	});

	it("verifies with fee successfully", () => {
		contract.setAuthorityContract("ST2TEST");
		contract.mockIssuerData.set("ST3ISSUER", {});
		contract.mockCredentialData.set(1, { hash: new Uint8Array(32).fill(1) });
		contract.mockRevocationStatus.set(1, false);
		const result = contract.verifyCredentialWithFee(
			1,
			"ST3ISSUER",
			new Uint8Array(32).fill(1),
			100,
			new Uint8Array(65).fill(2),
			"education",
			150
		);
		expect(result.ok).toBe(true);
		expect(result.value).toBe(0);
		const verification = contract.getVerification(0);
		expect(verification?.feePaid).toBe(150);
		expect(contract.stxTransfers).toEqual([
			{ amount: 150, from: "ST1TEST", to: "ST2TEST" },
		]);
	});

	it("rejects verification with fee below minimum", () => {
		contract.setAuthorityContract("ST2TEST");
		const result = contract.verifyCredentialWithFee(
			1,
			"ST3ISSUER",
			new Uint8Array(32).fill(1),
			100,
			new Uint8Array(65).fill(2),
			"education",
			50
		);
		expect(result.ok).toBe(false);
		expect(result.value).toBe(ERR_INVALID_FEE);
	});

	it("rejects batch verification with invalid size", () => {
		contract.setAuthorityContract("ST2TEST");
		const credentials: Array<{
			credId: number;
			issuer: string;
			hash: Uint8Array;
			exp: number;
			sig: Uint8Array;
			type: string;
		}> = [];
		const result = contract.batchVerifyCredentials(credentials);
		expect(result.ok).toBe(false);
		expect(result.value).toBe(ERR_INVALID_BATCH_SIZE);
	});

	it("sets min verification fee successfully", () => {
		contract.setAuthorityContract("ST2TEST");
		const result = contract.setMinVerificationFee(200);
		expect(result.ok).toBe(true);
		expect(result.value).toBe(true);
		expect(contract.state.minVerificationFee).toBe(200);
	});

	it("returns correct verification count", () => {
		contract.setAuthorityContract("ST2TEST");
		contract.mockIssuerData.set("ST3ISSUER", {});
		contract.mockCredentialData.set(1, { hash: new Uint8Array(32).fill(1) });
		contract.mockRevocationStatus.set(1, false);
		contract.verifyCredential(
			1,
			"ST3ISSUER",
			new Uint8Array(32).fill(1),
			100,
			new Uint8Array(65).fill(2),
			"education"
		);
		const result = contract.getVerificationCount();
		expect(result.ok).toBe(true);
		expect(result.value).toBe(1);
	});

	it("checks credential verified correctly", () => {
		contract.setAuthorityContract("ST2TEST");
		contract.mockIssuerData.set("ST3ISSUER", {});
		contract.mockCredentialData.set(1, { hash: new Uint8Array(32).fill(1) });
		contract.mockRevocationStatus.set(1, false);
		contract.verifyCredential(
			1,
			"ST3ISSUER",
			new Uint8Array(32).fill(1),
			100,
			new Uint8Array(65).fill(2),
			"education"
		);
		const result = contract.checkCredentialVerified(1);
		expect(result.ok).toBe(true);
		expect(result.value).toBe(true);
		const result2 = contract.checkCredentialVerified(2);
		expect(result2.ok).toBe(true);
		expect(result2.value).toBe(false);
	});

	it("rejects invalid authority contract", () => {
		const result = contract.setAuthorityContract(
			"SP000000000000000000002Q6VF78"
		);
		expect(result.ok).toBe(false);
		expect(result.value).toBe(false);
	});
});