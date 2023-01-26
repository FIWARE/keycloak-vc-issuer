import * as React from 'react';
import { AlertVariant } from '@patternfly/react-core';
interface ContentAlertProps {
}
interface ContentAlertState {
    alerts: {
        key: number;
        message: string;
        variant: AlertVariant;
    }[];
}
export declare class ContentAlert extends React.Component<ContentAlertProps, ContentAlertState> {
    private static instance;
    private constructor();
    /**
     * @param message A literal text message or localization key.
     */
    static success(message: string, params?: string[]): void;
    /**
     * @param message A literal text message or localization key.
     */
    static danger(message: string, params?: string[]): void;
    /**
     * @param message A literal text message or localization key.
     */
    static warning(message: string, params?: string[]): void;
    /**
     * @param message A literal text message or localization key.
     */
    static info(message: string, params?: string[]): void;
    private hideAlert;
    private getUniqueId;
    private postAlert;
    render(): React.ReactNode;
}
export {};
