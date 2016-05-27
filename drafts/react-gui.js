// ############### React code ###############

// A renderer for the radio buttons
var RadioButton = React.createClass({

	/**
	 * Render function for InputGroupBloc
	 */
	render: function() {
		var selected = (this.props.currentAction == this.props.inputValue);
		console.log('selected = ' + selected);
		return (
			<label className={ (selected) ? 'btn btn-info' : 'btn btn-info' } >
				<input type="radio" id={this.props.inputValue} name={this.props.inputName} checked={selected} value={this.props.inputValue} onChange={this.props.switchAction} /> {this.props.inputText}
			</label>
		);
	}
});


// A renderer for the input groups
var InputGroupBloc = React.createClass({

	/**
	 * Render function for InputGroupBloc
	 */
	render: function() {

		// If addon on right
		if (this.props.textOnLeft) return (
			<div className="input-group">
				<span className="input-group-addon">{this.props.addonText}</span>
				<input type={this.props.inputType} className="form-control" name={this.props.inputName} placeholder={this.props.inputPlaceholder} />
			</div>
		);

		// If addon on left
		else return (
			<div className="input-group">
				<input type={this.props.inputType} className="form-control" name={this.props.inputName} placeholder={this.props.inputPlaceholder} />
				<span className="input-group-addon">{this.props.addonText}</span>
			</div>
		);
	}
});


// The FormBloc renderer
var FormBloc = React.createClass({

	switchAction: function(optionChoosed) {
		this.state.action = optionChoosed.currentTarget.value;
		console.log("Action = " + optionChoosed.currentTarget.value);
		console.log("New action = " + this.state.action);
	},

	/**
	 * Getter of the initial state for parameters
	 */
	getInitialState: function() {
		return {
			action: 'analyse'
		};
	},

	/**
	 * Render function for FormBloc
	 */
	render: function() {

		// The things that will change in the view
		var url = 'http://127.0.0.1:2080';
		var fileTitle = 'Pcap field to ' + this.state.action;
		var optionsTitle = '';
		var optionInputName = '';
		var optionAddonText = '';

		// Analyse action
		if (this.state.action == 'analyse') {
			url += '/api/v1/testcase_analyse';
			optionsTitle = 'Analysis options';
			optionInputName = 'testcase_id';
			optionAddonText = 'Please choose a test case';

		// Dissect action
		} else {
			url += '/api/v1/frames_dissect';
			optionsTitle = 'Dissection options';
			optionInputName = 'protocol_selection';
			optionAddonText = 'Please choose a protocol';
		}

		return (
			<form action={url} method="post" enctype="multipart/form-data">
				<div className="col-sm-6">
					<div className="page-header">
						<h1>{fileTitle}</h1>
					</div>
					<InputGroupBloc inputName="pcap" inputType="file" addonText="Enter your pcap file" textOnLeft={true} inputPlaceholder="" />
				</div>

				<div className="col-sm-6">
					<div className="page-header">
						<h1>{optionsTitle}</h1>
					</div>
					<InputGroupBloc inputName="frame-number" inputType="text" addonText="Frame number" textOnLeft={true} inputPlaceholder="Enter a frame number if only one wanted" />

					<div style={{textAlign: 'center'}}>
						<div className="" >
							<RadioButton inputName="options" inputValue="analyse" inputText="Analyse" currentAction={this.state.action} switchAction={this.switchAction} />
							<RadioButton inputName="options" inputValue="dissect" inputText="Dissect" currentAction={this.state.action} switchAction={this.switchAction} />
						</div>
					</div>
				</div>

				<p style={{textAlign: 'center'}}>
					<input type="submit" value="Execute" className="btn btn-success centered-block" />
				</p>
			</form>
		);
	}
});


// The PcapForm renderer
var PcapForm = React.createClass({

	/**
	 * Render function for PcapForm
	 */
	render: function() {
		return (
			<div className="row">
				<FormBloc />
			</div>
		);
	}
});


ReactDOM.render(
	<PcapForm />,
	document.getElementById('content')
);