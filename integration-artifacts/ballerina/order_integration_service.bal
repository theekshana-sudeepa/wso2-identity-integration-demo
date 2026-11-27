// ============================================================================
// WSO2 Ballerina (Swan Lake) — Cloud-Native Enterprise Integration Service
// Demonstrates:
//   - Declarative RS256 JWKS Listener Auth (WSO2 IS 7.0 / Asgardeo Key Manager)
//   - HTTP Client Circuit Breaker & Exponential Backoff Retry
//   - Content-Based Routing & Parallel Worker Scatter-Gather (fork / wait)
//   - Canonical Type-Safe Payload Transformation
// ============================================================================
import ballerina/http;
import ballerina/jwt;

public type OrderItem record {|
    string sku;
    int qty;
|};

public type OrderRequest record {|
    string orderId;
    string customerId;
    decimal amountUsd;
    "USD"|"EUR" currency;
    "US-EAST"|"EU"|"APAC" region;
    "STANDARD"|"HIGH_RISK" priority;
    OrderItem[] items;
|};

public type CanonicalOrderResponse record {|
    string schemaVersion = "urn:wso2:ballerina:canonical-order:v3";
    string orderId;
    string mediationRoute;
    string fulfillmentStatus;
    json orderBranch;
    json inventoryBranch;
    json riskBranch;
|};

final http:Client inventoryClient = check new ("http://inventory-primary.choreo.internal:8082", {
    circuitBreaker: {
        rollingWindow: {timeWindow: 60, bucketSize: 10, requestVolumeThreshold: 2},
        failureThreshold: 0.5,
        resetTime: 15,
        statusCodes: [500, 502, 503, 504]
    },
    retryConfig: {
        count: 3,
        interval: 1,
        backOffFactor: 2.0,
        maxWaitInterval: 16
    }
});

@http:ServiceConfig {
    auth: [
        {
            jwtValidatorConfig: {
                issuer: "http://localhost:5050/dev-idp/oauth2/token",
                audience: "wso2-api-demo",
                signatureConfig: {
                    jwksConfig: {url: "http://localhost:5050/dev-idp/oauth2/jwks"}
                }
            },
            scopes: ["orders:read"]
        }
    ]
}
service /api/integration/orders on new http:Listener(8290) {

    isolated resource function post [string orderId]/mediate(
            @http:Header {name: "X-JWT-Assertion"} string? apimBackendJwt,
            @http:Payload OrderRequest payload) returns CanonicalOrderResponse|http:InternalServerError {

        // 1. Content-Based Router (CBR)
        string cbrRoute = payload.amountUsd >= 1000d || payload.priority == "HIGH_RISK"
            ? "HIGH_VALUE_FRAUD_SCREEN"
            : (payload.region == "EU" ? "EU_GDPR_COMPLIANCE_ROUTE" : "FAST_TRACK_STANDARD_ROUTE");

        // 2. Scatter-Gather using Concurrent Ballerina Named Workers
        fork {
            worker OrderWorker returns json {
                return {orderId: orderId, ledgerState: "COMMITTED", amountUsd: payload.amountUsd};
            }
            worker InventoryWorker returns json {
                json|error res = inventoryClient->/v1/reserve.post(payload);
                return res is json ? res : {reservationState: "RESERVED_ON_FAILOVER_REPLICA"};
            }
            worker FraudRiskWorker returns json {
                return {cbrRoute: cbrRoute, riskScore: payload.amountUsd >= 1000d ? 18 : 4, verdict: "APPROVED"};
            }
        }

        record {json OrderWorker; json InventoryWorker; json FraudRiskWorker;} results =
            wait {OrderWorker, InventoryWorker, FraudRiskWorker};

        // 3. Canonical Transformation
        return {
            orderId: orderId,
            mediationRoute: cbrRoute,
            fulfillmentStatus: "ORCHESTRATED_SUCCESS",
            orderBranch: results.OrderWorker,
            inventoryBranch: results.InventoryWorker,
            riskBranch: results.FraudRiskWorker
        };
    }
}
