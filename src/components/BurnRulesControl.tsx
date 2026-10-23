import { useState } from 'react';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Popover, PopoverContent, PopoverTrigger } from '@/components/ui/popover';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { HourglassIcon } from '@/components/ui/animated-hourglass';
import {
    BURN_TRIGGER_OPTIONS,
    BURN_UNIT_OPTIONS,
    type BurnUnit,
} from '@/lib/constants';

interface BurnRulesControlProps {
    trigger: string;
    onTriggerChange: (value: string) => void;
    timeValue: string;
    onTimeValueChange: (value: string) => void;
    unit: BurnUnit;
    onUnitChange: (value: BurnUnit) => void;
    unlockValue: string;
    onUnlockValueChange: (value: string) => void;
    disabled?: boolean;
    disabledReason?: string;
}

export function BurnRulesControl({
    trigger,
    onTriggerChange,
    timeValue,
    onTimeValueChange,
    unit,
    onUnitChange,
    unlockValue,
    onUnlockValueChange,
    disabled = false,
    disabledReason,
}: BurnRulesControlProps) {
    const [open, setOpen] = useState(false);

    const summary = trigger === 'off'
        ? 'No automatic burn'
        : trigger === 'time'
            ? `Delete after ${timeValue || '?'} ${BURN_UNIT_OPTIONS.find((option) => option.value === unit)?.label.toLowerCase() ?? unit}`
            : `Delete after ${unlockValue || '?'} unlock${unlockValue === '1' ? '' : 's'}`;

    return (
        <Popover open={open} onOpenChange={setOpen}>
            <PopoverTrigger asChild>
                <Button
                    type="button"
                    variant="outline"
                    className="w-full justify-start text-left font-normal"
                    disabled={disabled}
                >
                    <HourglassIcon size={16} className="mr-2 text-primary" />
                    <span className="truncate">{disabled ? (disabledReason ?? 'Burn rules unavailable') : summary}</span>
                </Button>
            </PopoverTrigger>
            <PopoverContent className="w-80 p-4" align="start">
                <div className="flex flex-col gap-4">
                    <div className="flex flex-col gap-1.5">
                        <Label htmlFor="burn-trigger">Burn trigger</Label>
                        <Select value={trigger} onValueChange={onTriggerChange}>
                            <SelectTrigger id="burn-trigger">
                                <SelectValue />
                            </SelectTrigger>
                            <SelectContent>
                                {BURN_TRIGGER_OPTIONS.map((option) => (
                                    <SelectItem key={option.value} value={option.value}>
                                        {option.label}
                                    </SelectItem>
                                ))}
                            </SelectContent>
                        </Select>
                    </div>

                    {trigger === 'time' && (
                        <div className="grid grid-cols-2 gap-2">
                            <div className="flex flex-col gap-1.5">
                                <Label htmlFor="burn-time">Duration</Label>
                                <Input
                                    id="burn-time"
                                    type="number"
                                    min={1}
                                    value={timeValue}
                                    onChange={(event) => onTimeValueChange(event.target.value)}
                                    placeholder="24"
                                />
                            </div>
                            <div className="flex flex-col gap-1.5">
                                <Label htmlFor="burn-unit">Unit</Label>
                                <Select
                                    value={unit}
                                    onValueChange={(value) => onUnitChange(value as BurnUnit)}
                                >
                                    <SelectTrigger id="burn-unit">
                                        <SelectValue />
                                    </SelectTrigger>
                                    <SelectContent>
                                        {BURN_UNIT_OPTIONS.map((option) => (
                                            <SelectItem key={option.value} value={option.value}>
                                                {option.label}
                                            </SelectItem>
                                        ))}
                                    </SelectContent>
                                </Select>
                            </div>
                        </div>
                    )}

                    {trigger === 'unlock_count' && (
                        <div className="flex flex-col gap-1.5">
                            <Label htmlFor="burn-unlocks">Unlock limit</Label>
                            <Input
                                id="burn-unlocks"
                                type="number"
                                min={1}
                                value={unlockValue}
                                onChange={(event) => onUnlockValueChange(event.target.value)}
                                placeholder="3"
                            />
                        </div>
                    )}

                    <p className="text-xs text-muted-foreground leading-relaxed">
                        {trigger === 'time' && 'The paste and its files are deleted automatically at the deadline.'}
                        {trigger === 'unlock_count' && 'When the share reaches this many views, the paste and its files are deleted.'}
                        {trigger === 'off' && 'The paste stays available until you delete it or change the rule.'}
                    </p>

                    <Button type="button" size="sm" onClick={() => setOpen(false)}>
                        Done
                    </Button>
                </div>
            </PopoverContent>
        </Popover>
    );
}
