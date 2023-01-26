import * as React from 'react';
interface ContentPageProps {
    title: string;
    introMessage?: string;
    onRefresh?: () => void;
    children: React.ReactNode;
}
/**
 * @author Stan Silvert ssilvert@redhat.com (C) 2019 Red Hat Inc.
 */
export declare class ContentPage extends React.Component<ContentPageProps> {
    constructor(props: ContentPageProps);
    render(): React.ReactNode;
}
export {};
