// DTOs match the TAK-CAD server plugin JSON wire format (camelCase).
// Field names confirmed from WinTAK plugin DLL (v1.0.0, April 2025).

export interface Address {
    streetName: string;
    city:       string;
    state:      string;
    zipCode:    string;
    country:    string;
}

export interface LatLon {
    latitudeDeg:  number;
    longitudeDeg: number;
}

export interface Location {
    address: Address | null;
    coords:  LatLon  | null;
}

export interface CallerInfo {
    uid:                  string;
    name:                 string | null;
    timestamp:            string | null;
    callerInfoType:       string | null;
    phoneNumber:          string | null;
    phoneContactMethod:   string | null;
    radioContactDetails:  string | null;
    otherContactDetails:  string | null;
}

export interface SourceSystem {
    uid:      string;
    name:     string;
    platform: string;
}

export interface Role {
    uid:  string;
    name: string;
}

export interface RoleRequirement {
    role:  Role;
    count: number;
}

export interface VehicleType {
    uid:  string;
    name: string;
}

export interface VehicleTypeRequirement {
    vehicleType: VehicleType;
    count:       number;
}

export interface IncidentTypeRef {
    uid:                  string;
    name:                 string;
    description:          string | null;
    requiredVehicleTypes: VehicleTypeRequirement[];
    requiredRoles:        RoleRequirement[];
}

export interface Note {
    uid:         string;
    info:        string;
    creator:     string;
    incidentUid: string;
    timestamp:   string | null;
}

export interface PersonCallsign {
    personUid: string;
    callsign:  string;
}

export interface VehicleCallsign {
    vehicleUid: string;
    assigned:   boolean;
}

export interface VehicleResponseStatus {
    vehicle:        VehicleCallsign;
    eta:            string | null;
    responseStatus: string | null;
}

export interface IncidentRef {
    uid:                       string;
    incidentName:              string;
    callerInfo:                CallerInfo | null;
    incidentTime:              string;
    firstResponderArrivalTime: string | null;
    incidentCompletionTime:    string | null;
    sourceSystem:              SourceSystem | null;
    incidentType:              IncidentTypeRef;
    dispatcher:                string | null;
    location:                  Location;
    details:                   string | null;
    requestedCallsigns:        string[];
    personnelResponding:       PersonCallsign[];
    vehiclesResponding:        VehicleResponseStatus[];
    status:                    string;
    notes:                     Note[];
    vehicleUidsRequested:      string[];
}

export interface IncidentMetadata {
    uid:          string;
    incidentName: string;
    incidentTime: string;
    incidentType: IncidentTypeRef;
    location:     Location;
    status:       string;
    dispatcher:   string | null;
}

export interface PersonRef {
    uid:         string;
    callsign:    string;
    takCadGroup: string | null;
    roles:       Role[];
}

export interface VehicleRef {
    uid:                           string;
    callsign:                      string;
    vehicleType:                   VehicleType | null;
    vehiclePersonnel:              PersonCallsign[];
    incidentsRequestingThisVehicle: string[];
}

export interface ResponseMessage {
    success:  boolean;
    result:   string | null;
    warnings: string[];
    errors:   string[];
}

// Incident status values observed in WinTAK DLL (Active/Cancelled UI tabs)
export const STATUS_ACTIVE    = 'ACTIVE';
export const STATUS_CANCELLED = 'CANCELLED';

export function isActive(status: string): boolean {
    return status !== STATUS_CANCELLED && status !== 'CLOSED';
}

export function formatAddress(loc: Location | null): string {
    if (!loc) return '';
    if (loc.address) {
        const a = loc.address;
        return [a.streetName, a.city, a.state].filter(Boolean).join(', ');
    }
    if (loc.coords) {
        return `${loc.coords.latitudeDeg.toFixed(5)}, ${loc.coords.longitudeDeg.toFixed(5)}`;
    }
    return '';
}

export function formatTime(iso: string | null): string {
    if (!iso) return '';
    try {
        return new Date(iso).toLocaleString();
    } catch {
        return iso;
    }
}

export function emptyLocation(): Location {
    return { address: { streetName: '', city: '', state: '', zipCode: '', country: '' }, coords: null };
}

export function emptyIncident(types: IncidentTypeRef[]): Partial<IncidentRef> {
    return {
        incidentName:         '',
        incidentType:         types[0] ?? undefined,
        incidentTime:         new Date().toISOString(),
        location:             emptyLocation(),
        status:               STATUS_ACTIVE,
        callerInfo:           null,
        dispatcher:           null,
        details:              null,
        notes:                [],
        requestedCallsigns:   [],
        vehicleUidsRequested: [],
        personnelResponding:  [],
        vehiclesResponding:   [],
    };
}
